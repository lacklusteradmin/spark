//! scripted verification harness. Not a user-facing product.
//!
//! layer 6, zone `boundary` — see `docs/layering.toml`.
//!
//! Above the FFI line: no cryptography, no protocol logic. Bindings only.
//!
//! This exists so gates can be checked by a script rather than by a person
//! driving a UI (`Spark-build-notes.md` §5: "the CLI is for scripted
//! verification, not for users").

#![forbid(unsafe_code)]

fn main() {
    println!(
        "spark {} ({})",
        env!("CARGO_PKG_VERSION"),
        spark_client::STAGE
    );
}
