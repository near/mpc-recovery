#[cfg(not(feature = "wasm"))]
pub mod hpke;

#[cfg(feature = "wasm")]
pub mod hpke {
    
}
