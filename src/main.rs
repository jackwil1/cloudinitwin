mod network_config;
mod user_data;
mod util;
mod volumes;

use std::{
    collections::HashMap, ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf,
    time::Duration,
};

use anyhow::anyhow;
use log::{debug, error, info, warn};
use secrecy::SecretBox;
use serde::Deserialize;
use windows::{
    Win32::{
        Foundation::{GetLastError, HANDLE, MAX_PATH},
        Security::{
            SE_PRIVILEGE_ENABLED, SE_SHUTDOWN_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES,
        },
        Storage::FileSystem::{GetDriveTypeW, GetLogicalDriveStringsW, GetVolumeInformationW},
        System::{
            Com::{
                COINIT_MULTITHREADED, CoInitializeEx, CoInitializeSecurity, CoUninitialize,
                EOAC_NONE, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
            },
            Diagnostics::Debug::OutputDebugStringW,
            Registry::HKEY_LOCAL_MACHINE,
            Shutdown::{
                InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED,
                SHTDN_REASON_MAJOR_OPERATINGSYSTEM, SHTDN_REASON_MINOR_RECONFIG,
            },
            Threading::{GetCurrentProcess, OpenProcessToken},
            WindowsProgramming::DRIVE_CDROM,
        },
        UI::Shell::{FOLDERID_ProgramFilesX64, KF_FLAG_DEFAULT, SHGetKnownFolderPath, StrCmpW},
    },
    core::{PCWSTR, w},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::ServiceControlHandlerResult,
    service_dispatcher,
};

const CONFIG_VOLUME_NAME: PCWSTR = w!("config-2");
const REBOOT_DELAY_SECONDS: u32 = 5;

fn get_config_drive() -> Option<OsString> {
    const MAX_DRIVES: usize = 26;
    const DRIVE_PATH_LEN: usize = 4; // "C:\"

    let mut drive_strings_raw = [0u16; (MAX_DRIVES + 1) * DRIVE_PATH_LEN];
    let len = unsafe { GetLogicalDriveStringsW(Some(&mut drive_strings_raw)) };

    if len == 0 {
        error!("Failed to get logical drives: {:?}", unsafe {
            GetLastError()
        });
        return None;
    }
    if len > drive_strings_raw.len() as u32 {
        error!("Buffer for logical drives is too small.");
        return None;
    }

    let drive_strings_slice = &drive_strings_raw[..len as usize];
    let drive_strings = drive_strings_slice
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty());

    let config_drives = drive_strings
        .filter_map(|drive_slice| {
            let drive_osstr = OsString::from_wide(drive_slice);
            let drive_str = drive_osstr.to_string_lossy();
            let drive_path_pcwstr = PCWSTR::from_raw(drive_slice.as_ptr());

            let is_cdrom = unsafe { GetDriveTypeW(drive_path_pcwstr) == DRIVE_CDROM };
            if !is_cdrom {
                debug!("Drive {drive_str} is not a CD-ROM drive");
                return None;
            }

            let mut volume_name = [0u16; MAX_PATH as usize];
            if let Err(e) = unsafe {
                GetVolumeInformationW(
                    drive_path_pcwstr,
                    Some(&mut volume_name),
                    None,
                    None,
                    None,
                    None,
                )
            } {
                error!("GetVolumeInformationW failed for drive {drive_str}: {e:?}");
                return None;
            }

            let is_config_drive =
                unsafe { StrCmpW(PCWSTR(volume_name.as_ptr()), CONFIG_VOLUME_NAME) == 0 };

            if is_config_drive {
                Some(drive_osstr)
            } else {
                debug!("Drive {drive_str} is not a config drive");
                None
            }
        })
        .collect::<Vec<_>>();

    if config_drives.is_empty() {
        return None;
    }

    if log::log_enabled!(log::Level::Debug) {
        for drive in &config_drives {
            debug!("Found config drive: {}", drive.to_string_lossy());
        }
    }

    if config_drives.len() > 1 {
        warn!("Multiple config drives found");
    }

    config_drives.into_iter().next()
}

#[derive(Deserialize, Debug)]
struct ConfigResource {
    content_path: String,
}

#[derive(Deserialize, Debug)]
struct Metadata {
    #[serde(rename = "uuid")]
    _uuid: String,
    network_config: ConfigResource,
    #[serde(rename = "admin_pass")]
    _admin_pass: SecretBox<Option<String>>,
    #[serde(default, rename = "public_keys")]
    _public_keys: HashMap<String, String>,
}

fn parse_metadata(config_drive: &OsString) -> anyhow::Result<Metadata> {
    let metadata_path: PathBuf = [
        config_drive,
        &OsString::from("openstack"),
        &OsString::from("latest"),
        &OsString::from("meta_data.json"),
    ]
    .into_iter()
    .collect();

    debug!("Metadata path: {}", metadata_path.to_string_lossy());

    let contents = std::fs::read_to_string(&metadata_path).map_err(|e| {
        anyhow!(
            "Failed to read metadata file '{}': {e}",
            metadata_path.to_string_lossy()
        )
    })?;

    serde_json::from_str(contents.as_str()).map_err(|e| anyhow!("Failed to parse metadata: {e}"))
}

fn schedule_reboot() -> anyhow::Result<()> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &mut token) }
        .map_err(|e| anyhow!("OpenProcessToken failed: {e:?}"))?;

    if token.is_invalid() {
        return Err(anyhow!("OpenProcessToken returned an invalid handle"));
    }

    let token = scopeguard::guard(token, |t| {
        if let Err(e) = unsafe { windows::Win32::Foundation::CloseHandle(t) } {
            warn!("Failed to close token handle: {e:?}");
        }
    });

    let mut tp = TOKEN_PRIVILEGES::default();
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    tp.PrivilegeCount = 1;
    unsafe {
        windows::Win32::Security::LookupPrivilegeValueW(
            None,
            SE_SHUTDOWN_NAME,
            &mut tp.Privileges[0].Luid,
        )
    }
    .map_err(|e| anyhow!("LookupPrivilegeValueW failed: {e:?}"))?;

    unsafe {
        windows::Win32::Security::AdjustTokenPrivileges(*token, false, Some(&tp), 0, None, None)
    }
    .map_err(|e| anyhow!("AdjustTokenPrivileges failed: {e:?}"))?;

    util::retry_std(|| unsafe {
        InitiateSystemShutdownExW(
            None,
            w!("Reboot after CloudInitWin"),
            REBOOT_DELAY_SECONDS,
            false,
            true,
            SHTDN_REASON_MAJOR_OPERATINGSYSTEM
                | SHTDN_REASON_MINOR_RECONFIG
                | SHTDN_REASON_FLAG_PLANNED,
        )
    })
    .map_err(|e| anyhow!("InitiateSystemShutdownExW failed: {e}"))?;

    Ok(())
}

fn get_install_dir() -> anyhow::Result<PathBuf> {
    let program_files_path =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramFilesX64, KF_FLAG_DEFAULT, None) }
            .map_err(|e| anyhow!("Failed to get Program Files path: {e:?}"))?;

    Ok(
        PathBuf::from(OsString::from_wide(unsafe { program_files_path.as_wide() }))
            .join("CloudInitWin"),
    )
}

fn configure_working_dir(install_dir: &PathBuf) -> anyhow::Result<()> {
    // This should have been created by the installer or even the logger library
    if !std::fs::exists(&install_dir)
        .map_err(|e| anyhow!("Failed to check if install dir exists: {e}"))?
    {
        return Err(anyhow!(
            "Install dir does not exist: {}",
            install_dir.to_string_lossy()
        ));
    }

    std::env::set_current_dir(&install_dir).map_err(|e| {
        anyhow!(
            "set_current_dir failed for '{}': {e}",
            install_dir.to_string_lossy()
        )
    })?;

    // Check our executable is running from the expected directory
    let expected_path = install_dir.join("CloudInitWin.exe");
    if !expected_path.exists() {
        return Err(anyhow!(
            "Expected executable path '{}' does not exist",
            expected_path.to_string_lossy()
        ));
    }

    let current_path = std::env::current_exe()
        .map_err(|e| anyhow!("Could not get current exe path: {e}"))?
        .canonicalize()
        .map_err(|e| anyhow!("Could not canonicalize current exe path: {e}"))?;
    if current_path
        != expected_path
            .canonicalize()
            .map_err(|e| anyhow!("Could not canonicalize expected path: {e}"))?
    {
        return Err(anyhow!(
            "Current executable path '{}' does not match expected path '{}'",
            current_path.to_string_lossy(),
            expected_path.to_string_lossy()
        ));
    }

    Ok(())
}

fn check_oobe_complete() -> anyhow::Result<bool> {
    let setup_in_progress = util::read_registry_dword(
        HKEY_LOCAL_MACHINE,
        w!("SYSTEM\\Setup"),
        w!("SystemSetupInProgress"),
    )
    .map_err(|e| anyhow!("Failed to read SystemSetupInProgress from registry: {e}"))?;

    let oobe_in_progress = util::read_registry_dword(
        HKEY_LOCAL_MACHINE,
        w!("SYSTEM\\Setup"),
        w!("OOBEInProgress"),
    )
    .map_err(|e| anyhow!("Failed to read OOBEInProgress from registry: {e}"))?;

    return Ok(setup_in_progress == 0 && oobe_in_progress == 0);
}

fn run_service(install_dir: &PathBuf) -> anyhow::Result<()> {
    info!("CloudInitWin started");

    info!("Ensuring OOBE is complete");
    while !check_oobe_complete().map_err(|e| anyhow!("Failed to check for OOBE completion: {e}"))? {
        debug!("Waiting...");
        std::thread::sleep(Duration::from_secs(1));
    }

    debug!("Install directory: {}", install_dir.to_string_lossy());

    debug!("Configuring working directory");
    configure_working_dir(install_dir)
        .map_err(|e| anyhow!("Failed to configure working directory: {e}"))?;

    let drive = get_config_drive();
    if drive.is_none() {
        warn!("No config drive found");
        return Ok(());
    }
    let drive = drive.unwrap();
    info!("Using config drive: {}", drive.to_string_lossy());

    let metadata = parse_metadata(&drive)?;
    info!("Read metadata: {metadata:?}");

    let network_config =
        network_config::parse_network_config(&metadata.network_config.content_path, &drive)?;
    info!("Read network config: {network_config:?}");

    let mut user_data = user_data::parse_user_data(&drive)?;
    info!("Read user data: {user_data:?}");

    info!("Initializing COM");
    unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
        .ok()
        .map_err(|e| anyhow!("CoInitialize failed: {e}"))?;
    scopeguard::defer! {
        info!("Uninitializing COM");
        unsafe { CoUninitialize() };
    }

    unsafe {
        CoInitializeSecurity(
            None,
            -1,
            None,
            None,
            RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            None,
            EOAC_NONE,
            None,
        )
    }
    .map_err(|e| anyhow!("CoInitializeSecurity failed: {e:?}"))?;

    // Handle user data first so it is more likely that we will be able to log in in the case of any errors
    info!("Handling user data");
    let needs_restart = match user_data::handle_user_data(&mut user_data) {
        Ok(needs_restart) => needs_restart,
        Err(e) => {
            error!("Failed to handle user data: {e}");
            false
        }
    };

    info!("Handling network config");
    if let Err(e) = network_config::handle_network_config(network_config) {
        error!("Failed to handle network config: {e}");
    }

    info!("Extending partitions");
    volumes::extend_partitions().map_err(|e| anyhow!("Failed to extend partitions: {e}"))?;

    info!("Configuration finished");

    if needs_restart {
        if let Err(e) = schedule_reboot() {
            error!("Failed to schedule reboot: {e}");
        }
        info!("Reboot scheduled successfully");
    } else {
        info!("No reboot needed");
    }

    return Ok(());
}

fn service_main(_arguments: Vec<OsString>) {
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle =
        windows_service::service_control_handler::register("CloudInitWin", event_handler)
            .expect("Failed to register service control handler");

    let install_dir = get_install_dir().unwrap();

    let logger_file_spec = flexi_logger::FileSpec::default()
        .directory(install_dir.join("Logs"))
        .basename("cloudinitwin")
        .suffix("log");

    flexi_logger::Logger::try_with_str("debug")
        .unwrap()
        .log_to_file(logger_file_spec)
        .start()
        .unwrap();

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set service status");

    match run_service(&install_dir) {
        Ok(_) => {
            info!("CloudInitWin run completed successfully");
        }
        Err(e) => {
            error!("CloudInitWin run failed: {e}");
        }
    }

    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Stopped,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        })
        .expect("Failed to set service status to stopped");
}

define_windows_service!(ffi_service_main, service_main);

fn main() {
    // Log panic information somewhere useful
    std::panic::set_hook(Box::new(|panic_info| {
        let panic_str = if let Some(s) = panic_info.payload().downcast_ref::<&str>() {
            format!("Panic occurred in CloudInitWin service: {s:?}")
        } else if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            format!("Panic occurred in CloudInitWin service: {s:?}")
        } else {
            format!("Panic occurred in CloudInitWin service")
        };
        let wide_str: Vec<u16> = panic_str.encode_utf16().chain(std::iter::once(0)).collect();
        unsafe { OutputDebugStringW(PCWSTR::from_raw(wide_str.as_ptr())) };

        error!("{}", panic_str);
    }));

    service_dispatcher::start("CloudInitWin", ffi_service_main)
        .expect("Failed to start service dispatcher");
}
