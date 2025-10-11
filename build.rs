// build.rs (en la raíz)
#[cfg(windows)]
fn main() {
    use std::env;
    // Permite override por variable de entorno; por defecto C:\NpcapSDK
    let sdk = env::var("NPCAP_SDK_DIR").unwrap_or_else(|_| String::from("C:\\NpcapSDK"));
    println!("cargo:rustc-link-search=native={}\\Lib\\x64", sdk);
}

#[cfg(not(windows))]
fn main() {}
