fn main() {
    println!("cargo::rustc-check-cfg=cfg(hs_native)");
    if pkg_config::Config::new().probe("libhs").is_ok() {
        println!("cargo:rustc-cfg=hs_native");
    }
}
