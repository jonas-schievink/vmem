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
