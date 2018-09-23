# vmem - Virtual Memory utilities

[![crates.io](https://img.shields.io/crates/v/vmem.svg)](https://crates.io/crates/vmem)
[![docs.rs](https://docs.rs/vmem/badge.svg)](https://docs.rs/vmem/)
[![Build Status](https://travis-ci.org/jonas-schievink/vmem.svg?branch=master)](https://travis-ci.org/jonas-schievink/vmem)

This crate provides a cross-platform (Windows and Unix) interface to virtual
memory allocation, protection, and mapping functions of the OS, as well as a
cross-platform way to register segmentation fault handlers.

If you're looking for memory-mapped file I/O, check out the [memmap] crate
instead.

Please refer to the [changelog](CHANGELOG.md) to see what changed in the last
releases.

[memmap]: https://github.com/danburkert/memmap-rs

## Usage

Start by adding an entry to your `Cargo.toml`:

```toml
[dependencies]
vmem = "0.1.0"
```

Then import the crate into your Rust code:

```rust
extern crate vmem;
```
