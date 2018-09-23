//! Paged virtual memory reservation and allocation.
//!
//! This crate provides a way to reserve address space (virtual memory) without
//! allocating RAM for the whole space, and allows subsequently allocating
//! arbitrary subranges of the reserved address space.
//!
//! The permissions (read, write, execute) of allocated memory can be changed
//! and a memory fault handler can be installed to react to invalid operations.
//!
//! The main use case of this is in emulators, where rebuilding the target
//! system's memory map can eliminate memory access checks and drastically
//! improve performance.
// TODO: Examples

#![doc(html_root_url = "https://docs.rs/vmem/0.1.0")]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

#[macro_use]
extern crate failure;
extern crate page_size;

#[cfg(unix)]
#[path = "unix.rs"]
mod imp;

#[cfg(windows)]
#[path = "windows.rs"]
mod imp;

pub mod signal_safe;

use failure::{Backtrace, Fail};

use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{fmt, io};
use std::os::raw::c_void;

/// Type of the memory fault handler installed by the library. Internally used.
///
/// Returns `true` when the fault happened in the watched memory region and the
/// user handler was invoked. The OS should then restore the context, which
/// allows the program to retry the access, or, if the context was modified
/// accordingly and the OS supports this, to skip the offending instruction.
///
/// If this returns `false`, the original handler should be invoked, which is
/// likely to be Rust's stack overflow detection handler. Note that this must
/// *not* deregister our handler, though. However, when this happens the program
/// will probably be aborted anyways.
type FaultHandler = unsafe fn(fault_addr: usize, context: *mut c_void) -> bool /* handled? */;

/// Ensures that only one signal handler is active at a time.
///
/// Attempting to register a signal handler while this is `true` will cause a
/// panic. Unregistering the signal handler will reset this to `false`.
///
/// The library sets this to `true` before registering the handler using the
/// platform-specific `imp` module, which blocks all future attempts to register
/// a handler until the handler is removed.
static FAULT_HANDLER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Information needed by registered signal handlers to determine
/// whether they should handle the fault.
struct HandlerInfo {
    /// Start address of the `ReservedMemory` area that is being
    /// watched.
    addr: usize,
    /// Length of the memory area being watched.
    len: usize,
    fault_handler: Option<Box<FnMut(&FaultInfo)>>,
}

static mut FAULT_HANDLER_INFO: HandlerInfo = HandlerInfo {
    addr: 0,
    len: 0,
    fault_handler: None,
};

/// Information about a segmentation fault.
#[derive(Debug)]
pub struct FaultInfo {
    /// Offset into the `ReservedMemory` that triggered the fault.
    ///
    /// The program made an attempt to access this address in a way that was not
    /// allowed by the page's configured `Protection`.
    pub fault_offset: usize,

    /// Pointer to the saved processor context.
    ///
    /// The context is an OS- and architecture-dependent structure containing
    /// register values. Depending on the operating system, you can modify the
    /// fields in here to change the processor state on return from the handler.
    ///
    /// Platform-specific details:
    /// * On POSIX systems, this points to a `ucontext_t` structure. The pointer
    ///   is obtained as an argument to the signal handling function
    ///   (`sa_sigaction`). Refer to [`sigaction(2)`] for details.
    /// * On Windows, this points to a `CONTEXT` structure. The pointer is
    ///   obtained through the `_EXCEPTION_POINTERS` structure passed to the
    ///   vectored exception handler registered by this library.
    ///
    /// [`sigaction(2)`]: http://man7.org/linux/man-pages/man2/sigaction.2.html
    pub context: *mut c_void,

    /// Keep the struct extensible without breaking changes.
    _private: (),
}

// FIXME This model is incompatible with Windows' (rather pathetic) huge page support
// Linux' THP should Just Work™, but we might want to expose `madvise`.

/// A contiguous chunk of reserved address space.
///
/// "Reserved" means that the memory will not be allocated for anything else by
/// application or OS as long as the corresponding `ReservedMemory` exists. It
/// does *not* mean that the memory is accessible or allocated. In fact, it is
/// guaranteed that any access to any byte within the `ReservedMemory` will
/// cause a segmentation fault or an equivalent error.
///
/// Parts of the reserved memory region can be allocated and made accessible by
/// calling [`allocate`][#method.allocate].
#[derive(Debug)]
pub struct ReservedMemory {
    addr: usize,
    len: usize,
    /// List of allocations created within this reservation. Range values are
    /// offsets into `self`.
    ///
    /// Behind a mutex that needs to be locked before any attempt at allocation
    /// is made. In particular, `imp::alloc` must only be called when this is
    /// locked. Failure to do so can result in the OS having a different view
    /// of our allocated memory than we do, and racing to allocate will then
    /// likely cause havoc.
    allocations: Mutex<Allocations>,
    owns_fault_handler: bool,
}

impl ReservedMemory {
    /// Reserves at least `bytes` Bytes of virtual memory.
    ///
    /// Failure to reserve memory will cause a panic.
    pub fn reserve(bytes: usize) -> Self {
        Self::try_reserve(bytes).expect("failed to reserve address space")
    }

    /// Tries to reserve at least `bytes` Bytes of virtual memory.
    ///
    /// Returns an error when the OS cannot allocate the memory. This is most
    /// likely to happen when allocating an extremely large amount, or when
    /// allocating moderate amounts on a heavily fragmented 32-bit system.
    pub fn try_reserve(bytes: usize) -> Result<Self, Error> {
        match imp::reserve(bytes) {
            Ok(ptr) => Ok(Self {
                addr: ptr as usize,
                len: bytes,
                allocations: Mutex::new(Allocations {
                    list: Vec::new(),
                }),
                owns_fault_handler: false,
            }),
            Err(e) => Err(ErrorKind::Os(e).into())
        }
    }

    /// Returns the starting address of the reserved memory region.
    ///
    /// This is always a page-aligned address.
    pub fn addr(&self) -> usize {
        self.addr
    }

    /// Returns the size of the reserved memory region in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the system's page size, the smallest amount of memory that can
    /// be manipulated by this library.
    ///
    /// Note that this is not necessarily the smallest amount of address space
    /// that can be allocated. For example, Windows might have a different
    /// address space allocation granularity (`dwAllocationGranularity` in
    /// [`SYSTEM_INFO`]).
    ///
    /// [`SYSTEM_INFO`]: https://msdn.microsoft.com/en-us/library/windows/desktop/ms724958(v=vs.85).aspx
    pub fn page_size(&self) -> usize {
        page_size::get()
    }

    /// Allocates pages inside this reserved memory section and makes them
    /// readable and writeable.
    ///
    /// The content of the pages is undefined. Don't assume allocated memory
    /// always starts out zeroed.
    ///
    /// After writing your data to the allocation, you can mark it as read-only
    /// or executable using `AllocatedMemory::set_protection`.
    ///
    /// # Parameters
    ///
    /// * `offset`: Offset into the reserved address space.
    /// * `bytes`: Number of bytes to allocate.
    // NB: This takes `&self` to allow multiple `AllocatedMemory` instances to
    // coexist. Otherwise a single one would permanently borrow `self`. It
    // should still be thread-safe.
    pub fn allocate(
        &self,
        offset: usize,
        bytes: usize,
    ) -> Result<AllocatedMemory, Error> {
        self.addr.checked_add(offset).and_then(|sum| sum.checked_add(bytes))
            .ok_or_else(|| ErrorKind::TooLarge)?;  // overflow

        if offset + bytes > self.len {
            return Err(ErrorKind::TooLarge.into());   // doesn't fit in `self`
        }

        if bytes == 0 {
            return Err(ErrorKind::ZeroSize.into());   // zero-sized allocation would be 0 pages, don't allow it
        }

        if offset & (self.page_size() - 1) != 0 {
            return Err(ErrorKind::NotAligned.into());   // not a multiple of the page size
        }

        // round the amount of memory up to full pages
        let bytes = bytes + self.page_size() - 1;       // move up
        let bytes = bytes & !(self.page_size() - 1);    // clear all lower bits

        let mut allocs = self.allocations.lock().unwrap();
        if allocs.find_allocation_overlapping(offset).is_ok() {
            return Err(ErrorKind::Overlap.into());   // overlaps existing allocation
        }

        let addr = self.addr + offset;
        imp::alloc(addr, bytes).map_err(ErrorKind::Os)?;

        allocs.register_allocation(offset, bytes);

        Ok(AllocatedMemory {
            addr,
            len: bytes,
            prot: Protection::ReadWrite,
            _p: PhantomData,
        })
    }
    // TODO: Test thread-safety of `allocate`

    /// Configures a memory fault handler to be run when an access inside this
    /// `ReservedMemory` region triggers a fault.
    ///
    /// Only one fault handler can be registered for the entire application.
    /// Attempting to register a handler while another one is already
    /// established will likely cause a panic (but note that external changes to
    /// the signal handlers can not be detected - changing the handlers
    /// externally will cause any fault to abort the program instead).
    ///
    /// The default action (when this handler isn't set) is to abort the
    /// process. When this handler is configured, it will be called instead and
    /// is given the opportunity to fix the fault condition. When the handler
    /// returns, the access will be retried. If the handler doesn't fix the
    /// fault condition, it will immediately be invoked again as the same fault
    /// will happen again.
    ///
    /// This can *not* be used as a protection against broken code that causes
    /// segmentation faults. It can only be used safely under well-controlled
    /// circumstances.
    ///
    /// # Safety
    ///
    /// **This function has numerous safety requirements that might be hard to
    /// get right. Take care!**
    ///
    /// Signal handlers are a global resource: Access to them must be externally
    /// synchronized. This function must not be called while other code might be
    /// setting signal handlers. It is recommended to call this once at
    /// application startup. While the library will guard against setting a
    /// handler while one is already in place, it can't prevent other libraries
    /// from changing handlers.
    ///
    /// On Unix-like systems, the handler must not call any async-signal unsafe
    /// functions. See [`signal-safety(7)`][man] for more info. The
    /// `signal_safe` module provides a few methods that are implemented using
    /// only signal-safe primitives.
    ///
    // TODO: Requirements on Windows
    ///
    /// [man]: http://man7.org/linux/man-pages/man7/signal-safety.7.html
    // The `F: 'static` requirement is unfortunate but (I think) required: While
    // technically all we need is `F: 'self`, `self` could be leaked, never
    // unregistering the fault handler, while could then be called after `'self`
    // has already expired.
    pub unsafe fn set_fault_handler<F>(&mut self, f: F)
    where F: Fn(&FaultInfo) + Sync + 'static {    // FIXME: Needs Send?
        if FAULT_HANDLER_REGISTERED.swap(true, Ordering::SeqCst) {
            // flag was already set
            panic!("a fault handler is already registered");
        }

        self.owns_fault_handler = true;

        // Safe: We've locked all access to the signal info by setting
        // `FAULT_HANDLER_REGISTERED` to `true`.
        FAULT_HANDLER_INFO.addr = self.addr;
        FAULT_HANDLER_INFO.len = self.len;
        FAULT_HANDLER_INFO.fault_handler = Some(Box::new(f));

        imp::register_fault_handler(fault_handler);

        unsafe fn fault_handler(fault_addr: usize, context: *mut c_void) -> bool /* handled? */ {
            let addr = FAULT_HANDLER_INFO.addr;
            let len = FAULT_HANDLER_INFO.len;
            if fault_addr >= addr
                && fault_addr < addr + len {

                (FAULT_HANDLER_INFO.fault_handler.as_mut().unwrap())(&FaultInfo {
                    fault_offset: fault_addr - addr,
                    context,
                    _private: (),
                });
                true
            } else {
                // Not in the watched range
                false
            }
        }

        // TODO: Test multi-threaded behaviour:
        // TODO: Race-conditions when registering a handler
        // TODO: Registering the handler, then faulting on a different thread
        // (or on 2 threads simultaneously - this must not yield 2 &mut to the
        // callback!)
    }

    /// Unregisters a fault handler previously set using `set_fault_handler`.
    ///
    /// Returns the handler passed to `set_fault_handler`, or `None` if no
    /// handler has been registered for this `ReservedMemory` instance.
    ///
    /// The handler will also be unregistered automatically when the
    /// corresponding `ReservedMemory` is dropped.
    ///
    /// After the handler is cleared, a new handler can be installed by calling
    /// `set_fault_handler` again.
    pub fn clear_fault_handler(&mut self) -> Option<Box<FnMut(&FaultInfo)>> {
        if self.owns_fault_handler {
            unsafe {
                imp::deregister_fault_handler();

                self.owns_fault_handler = false;
                let handler = FAULT_HANDLER_INFO.fault_handler.take();
                assert!(handler.is_some());

                // Release the fault handler lock. This must be done last.
                FAULT_HANDLER_REGISTERED.store(false, Ordering::SeqCst);

                handler
            }
        } else {
            None
        }
    }
}

impl Drop for ReservedMemory {
    fn drop(&mut self) {
        self.clear_fault_handler();
        unsafe {
            imp::unreserve(self.addr, self.len).expect("failed to deallocate memory");
        }
    }
}

/// List of allocated memory ranges inside a reserved chunk of address space.
#[derive(Debug)]
struct Allocations {
    list: Vec<Range<usize>>,
}

impl Allocations {
    fn register_allocation(&mut self, offset: usize, size: usize) {
        let idx = match self.find_allocation_overlapping(offset) {
            Ok(_) => {
                panic!(
                    "new allocation at offset {} and size {} overlaps existing one",
                    offset, size
                );
            }
            Err(idx) => idx,
        };

        self.list.insert(idx, offset..offset+size);
    }

    /// Finds an existing allocation that overlaps the given offset inside
    /// `self`.
    ///
    /// Returns the index into `self.allocations`.
    fn find_allocation_overlapping(&self, offset: usize) -> Result<usize, usize> {
        use std::cmp::Ordering;

        self.list.binary_search_by(|alloc| {
            if alloc.end <= offset {
                Ordering::Less
            } else if alloc.start > offset {
                Ordering::Greater
            } else {
                assert!(alloc.start <= offset && alloc.end > offset);
                Ordering::Equal
            }
        })
    }
}

/// A block of allocated memory.
///
/// Obtained via `ReservedMemory::allocate`. Note that the memory will *not* be
/// automatically deallocated when this is dropped. Instead, the whole memory
/// reservation along with all allocations contained within will be deallocated
/// when the `ReservedMemory` is dropped.
#[derive(Debug)]
pub struct AllocatedMemory<'a> {
    addr: usize,
    len: usize,
    prot: Protection,
    _p: PhantomData<&'a ()>,
}

impl<'a> AllocatedMemory<'a> {
    /// Returns the address of this allocated memory block.
    ///
    /// Starting at this address, `self.len()` bytes are accessible according to
    /// `self.protection()`. The user must make sure these bytes are used in a
    /// safe manner (no mutable aliasing, only transmute to any type `T` when
    /// the bytes at that location form a valid `T`, etc.). This is especially
    /// important in a multi-threaded setting, as no data races must occur.
    ///
    /// Note that neither the `AllocatedMemory` that logically owns the memory
    /// nor the `ReservedMemory` that logically owns the `AllocatedMemory` will
    /// attempt to access the allocated memory in any way. This allows having
    /// mutable access to the `AllocatedMemory`, while the actual memory at
    /// `self.addr()` is being immutably or mutably referenced or changed
    /// (possibly by another thread).
    pub fn addr(&self) -> usize {
        self.addr
    }

    /// Returns the size of this memory block in bytes.
    ///
    /// This is the number of contiguous bytes starting at `self.addr()` that
    /// can be accessed according to the current protection.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns the memory protection settings of this memory block.
    pub fn protection(&self) -> Protection {
        self.prot
    }

    /// Changes the memory protection settings of this block.
    ///
    /// When changing the memory area from being writeable to being read-only,
    /// you must ensure that no Rust references (whether immutable or mutable)
    /// to any part of the affected memory exist, since the compiler assumes
    /// that those always point to dereferenceable memory and may perform
    /// speculative reads that could then trap. In other word, this would be
    /// *undefined behaviour*, so don't do it.
    pub fn set_protection(&mut self, prot: Protection) {
        imp::protect(self.addr, self.len, prot)
            .expect("could not change protection");  // should never happen
        self.prot = prot;
    }
    // FIXME Test `set_protection` followed by `{set_,}protection`
}

/// Defines the protection level of a block of allocated memory.
///
/// Reserved address space can not be accessed at all (any attempt to do so
/// causes a segmentation fault or your platform's equivalent), while allocated
/// memory is at the very least readable, but may also be marked as writeable or
/// executable.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Protection {
    /// The memory is only readable.
    ///
    /// Attempts to write to the memory will cause a segmentation fault.
    /// Creating a `&mut T` pointing to any part of the memory is undefined
    /// behaviour, while creating a `&T` is okay as long as the data at the
    /// address is a valid `T` (the usual rules for casting uninitialized /
    /// zeroed memory to references apply).
    ReadOnly,
    /// The memory is readable and writeable.
    ReadWrite,
    /// The memory is readable and executable, but not writeable.
    ReadExecute,
    // TODO: Make extensible?
}

/// The error type used by this library.
#[derive(Debug)]
pub struct Error {
    inner: ErrorKind,
}

impl Fail for Error {
    fn cause(&self) -> Option<&Fail> {
        self.inner.cause()
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.inner.fmt(f)
    }
}

impl From<ErrorKind> for Error {
    fn from(e: ErrorKind) -> Self {
        Self { inner: e }
    }
}

#[derive(Fail, Debug)]
enum ErrorKind {
    #[fail(display = "operating system reported error: {}", _0)]
    Os(#[cause] io::Error),
    #[fail(display = "requested size is too large")]
    TooLarge,
    #[fail(display = "zero-sized allocation requested")]
    ZeroSize,
    #[fail(display = "requested allocation overlaps an existing one")]
    Overlap,
    #[fail(display = "requested location is not page-aligned")]
    NotAligned,
}

/*

Tests:
* Test for leaks
* `mem::forget` AllocatedMemory, then drop ReservedMemory normally - should not leak anything!
* SEGFAULT-inducing tests

*/

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn reserve() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        drop(mem);
    }

    #[test]
    fn alloc() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        mem.allocate(0, 1)
            .expect("failed to allocate page");
        mem.allocate(0, 1)
            .expect_err("allocated page twice");
        mem.allocate(page_size::get() - 1, 1)
            .expect_err("allocated first page twice (at end)");

        mem.allocate(page_size::get(), 1)
            .expect("failed to allocate second page");
        mem.allocate(page_size::get(), 1)
            .expect_err("allocated second page twice");
        mem.allocate(0, 1)
            .expect_err("allocated page twice");


        let mem = ReservedMemory::reserve(1024 * 1024);
        mem.allocate(0, page_size::get())
            .expect("failed to allocate");
        mem.allocate(page_size::get(), 1)
            .expect("failed to allocate second page");
    }

    #[test]
    fn alloc_same_page_different_offset() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        mem.allocate(0, 1)
            .expect("failed to allocate page");
        mem.allocate(1, 1)
            .expect_err("allocated page twice");
        mem.allocate(page_size::get()-10, 1)
            .expect_err("allocated page twice");
    }

    #[test]
    fn doesnt_fit() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        mem.allocate(1024 * 1024 - page_size::get(), page_size::get() + 1)
            .expect_err("allocated more than last page");
        mem.allocate(1024 * 1024, 1)
            .expect_err("allocated past last page");
        mem.allocate(1024 * 1024 * 256, 1)
            .expect_err("allocated past last page");

        mem.allocate(1024 * 1024 - page_size::get(), page_size::get())
            .expect("couldn't allocate last page");
    }

    #[test]
    fn page_boundary() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        mem.allocate(1024 + 1, 1)
            .expect_err("allocation not on page boundary succeeded");
    }

    #[test]
    fn absurdly_large() {
        ReservedMemory::try_reserve(1024 * 1024 * 1024 * 1024 * 500).unwrap_err();   // 500 TB
    }

    #[test]
    fn access() {
        let mem = ReservedMemory::reserve(1024 * 1024);
        let alloc = mem.allocate(0, page_size::get())
            .expect("failed to allocate");
        assert_eq!(alloc.protection(), Protection::ReadWrite);

        // Reading the allocated memory might yield garbage values, but should
        // be safe, since any byte is a valid `u8`.
        for addr in alloc.addr()..alloc.addr()+alloc.len() {
            unsafe {
                ptr::read_volatile(addr as *const u8);
                ptr::write_volatile(addr as *mut u8, 0xAB);
            }
        }
    }
}
