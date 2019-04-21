//! The Unix backend.

use crate::Protection;
use libc::{
    c_int, c_void, mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_PRIVATE, PROT_EXEC,
    PROT_NONE, PROT_READ, PROT_WRITE,
};
use std::{io, usize};

unsafe fn map(
    addr: usize,
    bytes: usize,
    prot: Option<Protection>,
    flags: c_int,
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
    unsafe { map(0, bytes, None, MAP_PRIVATE | MAP_ANONYMOUS) }
}

/// Allocate already reserved readable and writeable memory.
///
/// This can assume that `addr` is already reserved and that `bytes` fits in
/// the reserved memory.
pub fn alloc(addr: usize, bytes: usize) -> Result<(), io::Error> {
    unsafe {
        if mprotect(addr as *mut _, bytes, self::prot(Protection::ReadWrite)) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

// Deallocation would need to repeat the `mmap` with `PROT_NONE`.

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
