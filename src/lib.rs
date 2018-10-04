//! Paged virtual memory reservation and allocation.
//!
//! This crate provides a way to reserve address space (virtual memory) without
//! allocating RAM for the whole space, and allows subsequently allocating
//! arbitrary subranges of the reserved address space.
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

use failure::{Backtrace, Fail};

use std::marker::PhantomData;
use std::ops::Range;
use std::sync::Mutex;
use std::{fmt, io};

#[cfg(unix)]
mod imp {
    extern crate libc;

    use self::libc::{
        c_void, c_int, mmap, munmap, mprotect, PROT_NONE, PROT_READ, PROT_WRITE, PROT_EXEC,
        MAP_PRIVATE, MAP_ANONYMOUS, MAP_FIXED, MAP_FAILED
    };
    use Protection;
    use std::{io, usize};

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
}

#[cfg(windows)]
mod imp {
    extern crate winapi;

    use self::winapi::ctypes::c_void;
    use self::winapi::um::memoryapi::{VirtualAlloc, VirtualFree, VirtualProtect};
    use self::winapi::shared::minwindef::DWORD;
    use self::winapi::um::winnt::{
        MEM_RESERVE, MEM_COMMIT, MEM_RELEASE, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE,
        PAGE_EXECUTE_READ
    };

    use Protection;
    use std::{io, ptr, usize};

    /// Reserve address space without backing RAM anywhere in memory.
    pub fn reserve(bytes: usize) -> Result<*mut c_void, io::Error> {
        let ret = unsafe { VirtualAlloc(ptr::null_mut(), bytes, MEM_RESERVE, PAGE_NOACCESS) };
        if ret == ptr::null_mut() {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret)
        }
    }

    /// Allocate already reserved readable and writeable memory.
    ///
    /// This can assume that `addr` is already reserved and that `bytes` fits in
    /// the reserved memory.
    pub fn alloc(addr: usize, bytes: usize) -> Result<(), io::Error> {
        let ret = unsafe {
            VirtualAlloc(addr as *mut _, bytes, MEM_COMMIT, PAGE_READWRITE)
        };
        assert_eq!(addr, ret as usize);
        Ok(())
    }

    /// Free all mappings (allocations and reservations) overlapping any address
    /// between `addr` and `addr+bytes`.
    pub unsafe fn unreserve(addr: usize, _bytes: usize) -> Result<(), io::Error> {
        // size is not needed, the entire reserved block is freed
        let ret = VirtualFree(addr as *mut _, 0, MEM_RELEASE);

        if ret == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Changes the protection of a memory region allocated using `alloc`.
    pub fn protect(addr: usize, bytes: usize, prot: Protection) -> Result<(), io::Error> {
        unsafe {
            if VirtualProtect(addr as *mut _, bytes, self::prot(prot), ptr::null_mut()) == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    fn prot(prot: Protection) -> DWORD {
        match prot {
            Protection::ReadOnly => PAGE_READONLY,
            Protection::ReadWrite => PAGE_READWRITE,
            Protection::ReadExecute => PAGE_EXECUTE_READ,
        }
    }
}

/// A contiguous chunk of reserved address space.
///
/// "Reserved" means that the memory will not be allocated for anything else by
/// application or OS as long as the corresponding `ReservedMemory` exists. It
/// does *not* mean that the memory is accessible or allocated. In fact, it is
/// guaranteed that any access to any byte within the `ReservedMemory` will
/// cause a segmentation fault or an equivalent error.
#[derive(Debug)]
pub struct ReservedMemory {
    addr: usize,
    len: usize,
    /// List of allocations created within this reservation. Range value are
    /// offsets into `self`.
    ///
    /// Behind a mutex that needs to be locked before any attempt at allocation
    /// is made. In particular, `imp::alloc` must only be called when this is
    /// locked.
    allocations: Mutex<Allocations>,
}

impl ReservedMemory {
    /// Reserves at least `bytes` Bytes of virtual memory.
    ///
    /// Failure to reserve memory will cause a panic.
    pub fn reserve(bytes: usize) -> Self {
        Self::try_reserve(bytes).expect("failed to reserve address space")
    }

    /// Tries to reserve at least `bytes` Bytes of virtual memory.
    pub fn try_reserve(bytes: usize) -> Result<Self, Error> {
        match imp::reserve(bytes) {
            Ok(ptr) => Ok(Self {
                addr: ptr as usize,
                len: bytes,
                allocations: Mutex::new(Allocations {
                    list: Vec::new(),
                }),
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

    /// Returns the system's page size, the smallest amount of memory that can
    /// be allocated and manipulated by this library.
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
            _p: PhantomData,
        })
    }
}

impl Drop for ReservedMemory {
    fn drop(&mut self) {
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
/// reservation will be deallocated when the `ReservedMemory` is dropped.
#[derive(Debug)]
pub struct AllocatedMemory<'a> {
    addr: usize,
    len: usize,
    _p: PhantomData<&'a ()>,
}

impl<'a> AllocatedMemory<'a> {
    /// Returns the address of this allocated memory block.
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

    /// Changes the memory protection settings of this block.
    pub fn set_protection(&mut self, prot: Protection) {
        imp::protect(self.addr, self.len, prot)
            .expect("could not change protection")  // should never happen
    }
}

/// Defines the protection level of a block of allocated memory.
///
/// Reserved address space can not be accessed at all (any attempt to do so
/// causes a segmentation fault or your platform's equivalent), while allocated
/// memory is at the very least readable, but may also be marked as writeable or
/// executable.
#[derive(Debug, Copy, Clone)]
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

        // Reading the allocated memory might yield garbage values, but should
        // be safe, since any byte is a valid `u8`.
        for addr in alloc.addr()..alloc.addr()+alloc.len() {
            unsafe {
                ptr::read(addr as *const u8);
            }
        }
    }
}
