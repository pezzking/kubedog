//! Windows builds only: puts the icon and the version in kubedog.exe. Other systems: nothing.
//! (The check is on the system built *for*, so it also holds when building for Windows on a Mac.)

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=assets/icons/kubedog-windows.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    // arm64 is built with zig (scripts/release.sh), which brings its own resource compiler; mingw has none for arm64.
    if std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("aarch64") {
        if let Err(e) = with_zig() {
            println!("cargo:warning=no icon in kubedog.exe: {e}");
        }
        return;
    }
    let mut res = winresource::WindowsResource::new();
    res.set_icon("assets/icons/kubedog-windows.ico");
    res.set("ProductName", "Kubedog");
    res.set("FileDescription", "Kubedog");
    if let Err(e) = res.compile() {
        // A build without the icon still works; say why it's missing.
        println!("cargo:warning=no icon in kubedog.exe: {e}");
    }
}

/// The icon as a compiled resource, made by `zig rc` and handed to the linker.
fn with_zig() -> Result<(), String> {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").map_err(|e| e.to_string())?);
    std::fs::copy("assets/icons/kubedog-windows.ico", out.join("kubedog.ico")).map_err(|e| e.to_string())?;
    std::fs::write(out.join("kubedog.rc"), "1 ICON \"kubedog.ico\"\n").map_err(|e| e.to_string())?;
    let done = std::process::Command::new("zig").args(["rc", "/fo", "kubedog.res", "kubedog.rc"]).current_dir(&out).output().map_err(|e| format!("zig: {e}"))?;
    if !done.status.success() {
        return Err(String::from_utf8_lossy(&done.stderr).trim().to_string());
    }
    println!("cargo:rustc-link-arg-bins={}", out.join("kubedog.res").display());
    Ok(())
}
