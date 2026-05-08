//! Fuzz target for #71. The compute engine reads up to 64KB from a
//! WASM-controlled output pointer; the bound-check that decides how
//! many bytes to copy is `engine::wasm_output_len`. This target
//! drives that function with arbitrary `(output_ptr, memory_size,
//! max_output_size)` triples and pins the contract: never panics,
//! the returned length never exceeds the caller-supplied cap, and
//! never reads past the end of the supplied memory window.
//!
//! Run with: `cargo +nightly fuzz run wasm_output_len`.

#![no_main]

use libfuzzer_sys::fuzz_target;
use paraloom::compute::engine::wasm_output_len;

fuzz_target!(|data: &[u8]| {
    if data.len() < 16 {
        return;
    }
    let output_ptr = i32::from_le_bytes(data[0..4].try_into().unwrap());
    let memory_size =
        usize::try_from(u64::from_le_bytes(data[4..12].try_into().unwrap())).unwrap_or(usize::MAX);
    let max_output_size = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;

    let len = wasm_output_len(output_ptr, memory_size, max_output_size);
    assert!(len <= max_output_size);
    if output_ptr >= 0 && (output_ptr as usize) < memory_size {
        assert!(len <= memory_size - (output_ptr as usize));
    } else {
        assert_eq!(len, 0);
    }
});
