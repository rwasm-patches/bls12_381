//! RWASM-specific implementations using Fluentbase SDK precompiles
//!
//! This module provides optimized BLS12-381 operations when running in RWASM environment
//! using Fluentbase cryptographic precompiles: [fluentbase-crypto]
#[link(wasm_import_module = "fluentbase_v1preview")]
extern "C" {
    fn _bls12381_g1_add(p_ptr: *mut u8, q_ptr: *const u8);
    fn _bls12381_g1_double(p_ptr: *mut u8);
    fn _bls12381_g1_mul(p_ptr: *mut u8, q_ptr: *const u8);

    fn _tower_fp1_bls12381_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);
    fn _tower_fp1_bls12381_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);
    fn _tower_fp1_bls12381_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);

    fn _tower_fp2_bls12381_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);
    fn _tower_fp2_bls12381_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);
    fn _tower_fp2_bls12381_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8);

    fn _sys_bigint(p_ptr: *mut u8, q_ptr: *const u8);
}

/// Fp operations

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp1_bls12381_add(p_ptr, q_ptr, r_ptr);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp1_bls12381_sub(p_ptr, q_ptr, r_ptr);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp1_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp1_bls12381_mul(p_ptr, q_ptr, r_ptr);
    }
}

/// Fp2 operations

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp2_add(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp2_bls12381_add(p_ptr, q_ptr, r_ptr);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_fp2_sub(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp2_bls12381_sub(p_ptr, q_ptr, r_ptr);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn fp2_mul(p_ptr: *mut u8, q_ptr: *const u8, r_ptr: *const u8) {
    unsafe {
        _tower_fp2_bls12381_mul(p_ptr, q_ptr, r_ptr);
    }
}

/// Performs G1 point addition using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_g1_add(p_ptr: *mut u8, q_ptr: *const u8) {
    unsafe {
        _bls12381_g1_add(p_ptr, q_ptr);
    }
}

/// Performs G1 point doubling using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_g1_double(p_ptr: *mut u8) {
    unsafe {
        _bls12381_g1_double(p_ptr);
    }
}

/// Performs G1 point multiplication using RWASM precompile
#[inline]
#[cfg(target_arch = "wasm32")]
pub fn bls12381_g1_mul(p_ptr: *mut u8, q_ptr: *const u8) {
    unsafe {
        _bls12381_g1_mul(p_ptr, q_ptr);
    }
}

#[inline]
#[cfg(target_arch = "wasm32")]
pub fn sys_bigint(p_ptr: *mut u8, q_ptr: *const u8) {
    unsafe {
        _sys_bigint(p_ptr, q_ptr);
    }
}
