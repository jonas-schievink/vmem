extern crate libc;

use self::libc::{
    c_void, c_int, mmap, munmap, mprotect, PROT_NONE, PROT_READ, PROT_WRITE,
    PROT_EXEC, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FIXED, MAP_FAILED
};
use {FaultHandler, Protection};
use std::{io, mem, ptr, usize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::panic::catch_unwind;

unsafe fn map(
    addr: usize,
    bytes: usize,
    prot: Option<Protection>,
    flags: c_int
) -> Result<*mut c_void, io::Error> {
    let prot = prot.map(self::prot).unwrap_or(PROT_NONE);
    let ret = mmap(addr as *mut _, bytes, prot, flags, -1, 0);
    if ret == MAP_FAILED {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Reserve address space without backing RAM anywhere in memory.
pub fn reserve(bytes: usize) -> Result<*mut c_void, io::Error> {
    unsafe {
        map(0, bytes, None, MAP_PRIVATE | MAP_ANONYMOUS)
    }
}

/// Allocate already reserved readable and writeable memory.
///
/// This can assume that `addr` is already reserved and that `bytes` fits in
/// the reserved memory.
pub fn alloc(addr: usize, bytes: usize) -> Result<(), io::Error> {
    // FIXME: The memory is already mapped, is `mprotect` enough
    let ret = unsafe {
        map(addr, bytes, Some(Protection::ReadWrite), MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED)?
    };
    assert_eq!(addr, ret as usize);
    Ok(())
}

/// Free all mappings (allocations and reservations) overlapping any address
/// between `addr` and `addr+bytes`.
pub unsafe fn unreserve(addr: usize, bytes: usize) -> Result<(), io::Error> {
    if munmap(addr as *mut _, bytes) == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// Changes the protection of a memory region allocated using `alloc`.
pub fn protect(addr: usize, bytes: usize, prot: Protection) -> Result<(), io::Error> {
    unsafe {
        if mprotect(addr as *mut _, bytes, self::prot(prot)) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

fn prot(prot: Protection) -> c_int {
    match prot {
        Protection::ReadOnly => PROT_READ,
        Protection::ReadWrite => PROT_READ | PROT_WRITE,
        Protection::ReadExecute => PROT_READ | PROT_EXEC,
    }
}

union SigAct {
    sigaction: libc::sigaction,
    nil: (),
}

/// Stores Rust's fault handler when another one is set.
static mut OLD_HANDLER: SigAct = SigAct { nil: () };

/// Registers a signal handler to be invoked on invalid memory accesses (aka a
/// SIGSEGV handler).
///
/// This is guaranteed to only be invoked in a locked fashion. No 2 threads will
/// call this at once.
pub unsafe fn register_fault_handler(handler: FaultHandler) {
    // We should be able to store Rust's signal handler and swap it back in when
    // our handler doesn't handle the fault. The faulting instruction will then
    // be retried, fault again, this time invoking Rust's handler. This way we
    // won't lose the stack overflow message.

    // Store the `FaultHandler` to be invoked by the Unix signal handler.
    static HANDLER: AtomicUsize = AtomicUsize::new(0);
    HANDLER.store(handler as usize, Ordering::SeqCst);


    let mut sigset: libc::sigset_t = mem::uninitialized();
    assert_eq!(libc::sigemptyset(&mut sigset), 0);
    let sigact = libc::sigaction {
        sa_sigaction: native_handler as usize,
        sa_mask: sigset,
        sa_flags: libc::SA_ONSTACK | libc::SA_SIGINFO,
        sa_restorer: None,
    };
    if libc::sigaction(libc::SIGSEGV, &sigact, &mut OLD_HANDLER.sigaction) == -1 {
        // `sigaction` is only expected to fail if the library passed wrong
        // arguments, so just panic in that case
        panic!("sigaction returned error: {}", io::Error::last_os_error());
    }

    assert!(
        OLD_HANDLER.sigaction.sa_flags & libc::SA_SIGINFO != 0,
        "old handler not a SA_SIGINFO handler"
    );

    unsafe extern fn native_handler(signal: c_int, info: *const libc::siginfo_t, context: *mut c_void) {
        // FIXME: Add the `si_addr` field to libc's `siginfo_t` (it's POSIX)
        // Copied from Rust's stack_overflow.rs
        #[repr(C)]
        #[allow(non_camel_case_types)]
        struct siginfo_t {
            a: [libc::c_int; 3], // si_signo, si_errno, si_code
            si_addr: *mut libc::c_void,
        }

        let fault_addr = (*(info as *const siginfo_t)).si_addr as usize;

        let handler: FaultHandler = mem::transmute(HANDLER.load(Ordering::SeqCst));
        if !handler(fault_addr, context as *mut _) {
            // `false` => handler didn't match.
            let old_sigaction = &OLD_HANDLER.sigaction;
            let handler: fn(c_int, *const libc::siginfo_t, *mut c_void)
                = mem::transmute(old_sigaction.sa_sigaction);

            if let Err(_) = catch_unwind(|| handler(signal, info, context)) {
                let msg = b"signal handler attempted to unwind - aborting process\n";
                write_stderr(msg).ok();
                libc::abort();
            }
        }
    }
}

/// Deregisters a fault handler previously registered using
/// `register_fault_handler`.
///
/// May only be called after `register_fault_handler`.
///
/// Restores Rust's fault handlers.
pub unsafe fn deregister_fault_handler() {
    sigaction(libc::SIGSEGV, &OLD_HANDLER.sigaction, None);
}

unsafe fn sigaction(signal: c_int, act: &libc::sigaction, old_act: Option<&mut libc::sigaction>) {
    let old_act = match old_act {
        Some(act) => act,
        None => ptr::null_mut(),
    };

    if libc::sigaction(signal, act, old_act) == -1 {
        // `sigaction` is only expected to fail if the library passed wrong
        // arguments, so just panic in that case
        panic!("sigaction returned error: {}", io::Error::last_os_error());
    }
}

pub fn write_stdout(buf: &[u8]) -> Result<usize, ()> {
    write_fd(libc::STDOUT_FILENO, buf)
}

pub fn write_stderr(buf: &[u8]) -> Result<usize, ()> {
    write_fd(libc::STDERR_FILENO, buf)
}

fn write_fd(fd: c_int, buf: &[u8]) -> Result<usize, ()> {
    unsafe {
        let result = libc::write(fd, buf.as_ptr() as *const _, buf.len());
        if result == -1 {
            Err(())
        } else {
            Ok(result as usize)
        }
    }
}
