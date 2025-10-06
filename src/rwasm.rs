//! RWASM-specific implementations using Fluentbase SDK precompiles
//!
//! This module provides optimized BLS12-381 operations when running in RWASM environment
//! using Fluentbase cryptographic precompiles: [fluentbase-crypto]
#[link(wasm_import_module = "fluentbase_v1preview")]
extern "C" {
    fn _bls12381_add(p_offset: i32, q_offset: i32);
    fn _bls12381_decompress(p_offset: i32, sign: u32);
    fn _bls12381_double(p_offset: i32);

    fn _tower_fp1_bls12381_add(p_offset: i32, q_offset: i32);
    fn _tower_fp1_bls12381_sub(p_offset: i32, q_offset: i32);
    fn _tower_fp1_bls12381_mul(p_offset: i32, q_offset: i32);

    fn _tower_fp2_bls12381_add(
        p_c0_offset: i32,
        p_c1_offset: i32,
        q_c0_offset: i32,
        q_c1_offset: i32,
    );
    fn _tower_fp2_bls12381_sub(
        p_c0_offset: i32,
        p_c1_offset: i32,
        q_c0_offset: i32,
        q_c1_offset: i32,
    );
    fn _tower_fp2_bls12381_mul(
        p_c0_offset: i32,
        p_c1_offset: i32,
        q_c0_offset: i32,
        q_c1_offset: i32,
    );

    fn _uint256_mul_mod(x_ptr: *mut u8, y_ptr: *const u8, m_ptr: *const u8);
}

/// Fp operations
/// Each Fp element is 48 bytes (6 * u64)

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        // The syscall takes 2 offsets (a, b) and writes result to the first parameter location
        // p_ptr: output, q_ptr: first input (a), r_ptr: second input (b)
        let a_offset = q_ptr as i32;
        let b_offset = r_ptr as i32;

        _tower_fp1_bls12381_add(a_offset, b_offset);

        // Copy result from q_ptr to p_ptr (48 bytes for one Fp element)
        core::ptr::copy(q_ptr, p_ptr, 48);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        let a_offset = q_ptr as i32;
        let b_offset = r_ptr as i32;

        _tower_fp1_bls12381_sub(a_offset, b_offset);

        core::ptr::copy(q_ptr, p_ptr, 48);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        let a_offset = q_ptr as i32;
        let b_offset = r_ptr as i32;

        _tower_fp1_bls12381_mul(a_offset, b_offset);

        core::ptr::copy(q_ptr, p_ptr, 48);
    }
}

/// Fp2 operations
/// Each Fp2 element consists of two Fp elements (c0 and c1), each 48 bytes

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp2_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        // p_ptr: output location for result
        // q_ptr: first input (a), r_ptr: second input (b)
        // Each Fp is 48 bytes, so c1 is at offset +48 from c0
        // The 4 parameters are offsets for: a_c0, a_c1, b_c0, b_c1
        // Result is written to the first input location (a), so we copy it to output
        let a_c0_offset = q_ptr as i32;
        let a_c1_offset = a_c0_offset + 48;
        let b_c0_offset = r_ptr as i32;
        let b_c1_offset = b_c0_offset + 48;

        _tower_fp2_bls12381_add(a_c0_offset, a_c1_offset, b_c0_offset, b_c1_offset);

        // Copy result from q_ptr to p_ptr (96 bytes = 2 * 48 for two Fp elements)
        core::ptr::copy(q_ptr, p_ptr, 96);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp2_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        let a_c0_offset = q_ptr as i32;
        let a_c1_offset = a_c0_offset + 48;
        let b_c0_offset = r_ptr as i32;
        let b_c1_offset = b_c0_offset + 48;

        _tower_fp2_bls12381_sub(a_c0_offset, a_c1_offset, b_c0_offset, b_c1_offset);

        core::ptr::copy(q_ptr, p_ptr, 96);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp2_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        let a_c0_offset = q_ptr as i32;
        let a_c1_offset = a_c0_offset + 48;
        let b_c0_offset = r_ptr as i32;
        let b_c1_offset = b_c0_offset + 48;

        _tower_fp2_bls12381_mul(a_c0_offset, a_c1_offset, b_c0_offset, b_c1_offset);

        core::ptr::copy(q_ptr, p_ptr, 96);
    }
}

/// Performs BLS12-381 point addition using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_add(p_ptr: *mut u8, q_ptr: *const u8) {
    unsafe {
        _bls12381_add(p_ptr as i32, q_ptr as i32);
    }
}

/// Performs BLS12-381 point decompression using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_decompress(p_ptr: *mut u8, sign: u32) {
    unsafe {
        _bls12381_decompress(p_ptr as i32, sign);
    }
}

/// Performs BLS12-381 point doubling using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_double(p_ptr: *mut u8) {
    unsafe {
        _bls12381_double(p_ptr as i32);
    }
}

/// Legacy G1 aliases for backward compatibility
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_g1_add(p_ptr: *mut u8, q_ptr: *const u8) {
    bls12381_add(p_ptr, q_ptr);
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_g1_double(p_ptr: *mut u8) {
    bls12381_double(p_ptr);
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn uint256_mul_mod(x: &[u8; 32], y: &[u8; 32], m: &[u8; 32]) -> [u8; 32] {
    let mut result = *x;
    unsafe {
        _uint256_mul_mod(result.as_mut_ptr(), y.as_ptr(), m.as_ptr());
    }
    result
}
