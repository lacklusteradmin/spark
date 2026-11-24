//! Give the Apple dynamic library a relocatable install name.
//!
//! Left alone, the linker records the library's absolute output path as its
//! LC_ID_DYLIB install name. That path is the builder's directory: it ships inside
//! the library, and two builds in different directories differ by it, which
//! `scripts/verify-reproducible.sh` catches. `@rpath/` is what an app that embeds
//! the library expects anyway.

fn main() {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" || os == "ios" {
        println!("cargo::rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libspark_ffi.dylib");
    }
}
