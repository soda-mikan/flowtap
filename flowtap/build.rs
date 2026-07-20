use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../flowtap-ebpf");
    println!("cargo:rerun-if-changed=../flowtap-common");

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("read Cargo workspace metadata")?;

    let package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "flowtap-ebpf")
        .ok_or_else(|| anyhow!("flowtap-ebpf package not found"))?;

    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = package;
    let package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("flowtap-ebpf manifest has no parent"))?
            .as_str(),
        ..Default::default()
    };

    aya_build::build_ebpf([package], Toolchain::default())
}
