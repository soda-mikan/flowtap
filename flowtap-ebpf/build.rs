fn main() {
    // Cargo cannot yet express bpf-linker as an artifact dependency. Tracking
    // the resolved executable at least rebuilds the object when it changes.
    let linker = which::which("bpf-linker").expect("bpf-linker must be installed and in PATH");
    println!("cargo:rerun-if-changed={}", linker.display());
}
