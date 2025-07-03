fn main() {
    windows_exe_info::versioninfo::VersionInfo::from_cargo_env_ex(
        None,
        Some("CloudInitWin"),
        Some("GPL-3.0-or-later"),
        None
    ).link().unwrap();
}
