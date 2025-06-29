use std::process::Command;

use log::{debug, warn};
use windows::{core::PCWSTR, Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_READ, REG_DWORD, REG_VALUE_TYPE}};
use anyhow::anyhow;

pub fn run_powershell_command(command: &str) -> anyhow::Result<String> {
    debug!("Running PowerShell command: {}", command);
    let output = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", command])
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(anyhow::anyhow!("PowerShell command failed: {}", stderr))
    } else {
        let stdout = String::from_utf8(output.stdout)?;
        Ok(stdout)
    }
}

const RETRY_DELAY_MS: u64 = 500;
const RETRY_COUNT: usize = 5;

pub fn retry_std<T, E>(f: impl FnMut() -> Result<T, E>) -> Result<T, retry::Error<E>> {
    retry::retry(retry::delay::Fixed::from_millis(RETRY_DELAY_MS).take(RETRY_COUNT), f)
}

pub fn read_registry_dword(root_key: HKEY, sub_key: PCWSTR, value_name: PCWSTR) -> anyhow::Result<u32> {
    let mut hkey = HKEY::default();
    retry_std(|| {
        unsafe {
            RegOpenKeyExW(
                root_key,
                sub_key,
                Some(0),
                KEY_READ,
                &mut hkey,
            )
        }
        .ok()
    })
    .map_err(|e| anyhow!("RegOpenKeyExW failed: {e:?}"))?;

    if hkey.is_invalid() {
        return Err(anyhow!("RegOpenKeyExW returned an invalid handle"));
    }
    
    let hkey = scopeguard::guard(hkey, |h| {
        let res = unsafe { windows::Win32::System::Registry::RegCloseKey(h) };
        if res.is_err() {
            warn!("RegCloseKey failed: {}", res.to_hresult());
        }
    });

    let mut data = 0u32;
    let mut data_size = std::mem::size_of::<u32>() as u32;
    let mut data_type = REG_VALUE_TYPE::default();

    retry_std(|| {
        unsafe {
            RegQueryValueExW(
                *hkey,
                value_name,
                None,
                Some(&mut data_type),
                Some(&mut data as *mut u32 as _),
                Some(&mut data_size),
            )
        }
        .ok()
    })
    .map_err(|e| anyhow!("RegQueryValueExW failed: {e:?}"))?;

    if data_type != REG_DWORD {
        return Err(anyhow!("Expected REG_DWORD type, got {:?}", data_type));
    }

    Ok(data)
}