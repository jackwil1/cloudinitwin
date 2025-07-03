use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::PathBuf};

use anyhow::anyhow;
use log::{debug, error, info, warn};
use secrecy::{ExposeSecret, SecretBox};
use serde::Deserialize;
use windows::{
    Win32::{
        Networking::ActiveDirectory::IADsUser,
        UI::Shell::{FOLDERID_ProgramData, KF_FLAG_DEFAULT, SHGetKnownFolderPath},
    },
    core::{BSTR, Interface, PCWSTR},
};

use crate::util;

#[derive(Deserialize, Debug)]
pub struct PasswordPolicy {
    expire: bool,
}

#[derive(Deserialize, Debug)]
pub struct UserData {
    pub hostname: String,
    manage_etc_hosts: bool,
    pub fqdn: String,

    user: Option<String>,
    users: Option<Vec<String>>,
    #[serde(default)]
    disable_root: bool,
    password: SecretBox<Option<String>>,
    #[serde(default)]
    ssh_authorized_keys: Vec<String>,
    chpasswd: PasswordPolicy,
    #[serde(default)]
    package_upgrade: bool,
}

pub fn parse_user_data(config_drive: &OsString) -> anyhow::Result<UserData> {
    let user_data_path: PathBuf = [
        config_drive,
        &OsString::from("openstack"),
        &OsString::from("latest"),
        &OsString::from("user_data"),
    ]
    .into_iter()
    .collect();

    debug!("User data path: {}", user_data_path.to_string_lossy());

    let contents = std::fs::read_to_string(&user_data_path)
        .map_err(|e| anyhow!("Failed to read user data file: {e}"))?;

    // Quote the `password: ...` value if it exists since it may otherwise be malformed yaml
    let contents_safe = contents
        .lines()
        .map(|line| {
            if line.starts_with("password:") {
                let parts: Vec<&str> = line.splitn(2, ':').collect();
                if parts.len() == 2 {
                    format!("{}: \"{}\"", parts[0], parts[1].trim())
                } else {
                    line.to_string()
                }
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");

    serde_yaml_ng::from_str(contents_safe.as_str())
        .map_err(|e| anyhow!("Failed to parse user data: {}", e))
}

fn set_user_password(user: &str, password: &str, expire: bool) -> anyhow::Result<()> {
    debug!("Setting password for {user}");
    let user_path: Vec<u16> = format!("WinNT://./{user}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut ido: Option<IADsUser> = None;
    util::retry_std(|| unsafe {
        windows::Win32::Networking::ActiveDirectory::ADsGetObject(
            PCWSTR::from_raw(user_path.as_ptr()),
            &IADsUser::IID,
            std::mem::transmute(&mut ido),
        )
    })
    .map_err(|e| anyhow!("ADsGetObject failed to get user: {e}"))?;

    let ido = ido.ok_or_else(|| anyhow!("ADsGetObject did not return a value"))?;

    util::retry_std(|| unsafe { ido.SetPassword(&BSTR::from(password)) })
        .map_err(|e| anyhow!("SetPassword failed: {e}"))?;

    if expire {
        // Set password to expire - force user to change password on next logon
        debug!("Setting password to expire on next logon"); // Use PowerShell command to set password expiry since COM interface is complex
        let command = format!(
            "Get-LocalUser -Name '{}' | Set-LocalUser -PasswordNeverExpires $false",
            user
        );
        util::run_powershell_command(&command)
            .map_err(|e| anyhow!("Failed to set password expiry: {e}"))?;

        // Force password change on next logon using PowerShell
        let command = format!("net user '{}' /logonpasswordchg:yes", user);
        util::run_powershell_command(&command)
            .map_err(|e| anyhow!("Failed to force password change on next logon: {e}"))?;
    } else {
        // Ensure password doesn't expire
        debug!("Setting password to not expire");
        let command = format!(
            "Get-LocalUser -Name '{}' | Set-LocalUser -PasswordNeverExpires $true",
            user
        );
        util::run_powershell_command(&command)
            .map_err(|e| anyhow!("Failed to set password to never expire: {e}"))?;
    }

    Ok(())
}

fn get_ssh_dir() -> anyhow::Result<PathBuf> {
    let program_data_path =
        unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
            .map_err(|e| anyhow!("Failed to get Program Data path: {e:?}"))?;

    Ok(PathBuf::from(OsString::from_wide(unsafe { program_data_path.as_wide() })).join("ssh"))
}

fn handle_ssh_keys(ssh_authorized_keys: &Vec<String>) -> anyhow::Result<()> {
    if ssh_authorized_keys.is_empty() {
        debug!("No SSH authorized keys provided, skipping SSH setup");
        return Ok(());
    }

    // Enable windows SSH
    info!("Installing and enabling Windows SSH server service");
    if let Err(e) = util::run_powershell_command(
        r#"if (!(Get-WindowsCapability -Online -Name OpenSSH.Server -ErrorAction SilentlyContinue)) {
            Add-WindowsCapability -Online -Name OpenSSH.Server;
        }
        Start-Service sshd;
        Set-Service -Name sshd -StartupType "Automatic"
        $existingRule = Get-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -ErrorAction SilentlyContinue
        if ($existingRule) {
            Set-NetFirewallRule -Name "OpenSSH-Server-In-TCP" -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any
        } else {
            New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -Profile Any
        }
        if (!(Get-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -ErrorAction SilentlyContinue)) {
            New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell -PropertyType String -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Force
        }"#,
    ) {
        error!("Failed to install and enable Windows SSH server service: {e}");
    }

    info!("Adding SSH authorized keys");

    // Create the authorized_keys file if it doesn't exist
    let ssh_dir = get_ssh_dir().map_err(|e| anyhow!("Failed to get ssh dir: {e}"))?;
    if !ssh_dir.exists() {
        return Err(anyhow!(
            "SSH directory does not exist: {}",
            ssh_dir.to_string_lossy()
        ));
    }
    let authorized_keys_path = ssh_dir.join("administrators_authorized_keys");
    if !authorized_keys_path.exists() {
        info!(
            "Creating authorized_keys file at: {}",
            authorized_keys_path.to_string_lossy()
        );
        std::fs::File::create(&authorized_keys_path)
            .map_err(|e| anyhow!("Failed to create authorized_keys file: {e}"))?;

        debug!("Setting permissions for administrators_authorized_keys file");
        if let Err(e) = util::run_powershell_command(&format!(
            r#"icacls.exe $env:ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant "Administrators:F" /grant "SYSTEM:F" "#
        )) {
            error!("Failed to set permissions for administrators_authorized_keys file: {e}");
        }
    }

    for key in ssh_authorized_keys {
        debug!("Handling SSH key: {}", key);

        // Add the SSH key to the authorized_keys file if it's not already present
        let mut authorized_keys_content = std::fs::read_to_string(&authorized_keys_path)
            .map_err(|e| anyhow!("Failed to read authorized_keys file: {e}"))?;
        if !authorized_keys_content.contains(key) {
            info!("Adding key to authorized_keys file: {}", key);
            authorized_keys_content.push_str(&format!("\n{key}\n"));
            std::fs::write(&authorized_keys_path, authorized_keys_content)
                .map_err(|e| anyhow!("Failed to write to authorized_keys file: {e}"))?;
        } else {
            info!("SSH key already exists in authorized_keys file: {}", key);
        }
    }

    Ok(())
}

pub fn handle_user_data(user_data: &mut UserData) -> anyhow::Result<()> {
    debug!("Handling user data: {:?}", user_data);

    if user_data.disable_root {
        warn!("disable_root is not supported");
    }

    let user: String = match (&user_data.users, &user_data.user) {
        (Some(_), Some(_)) => {
            return Err(anyhow!("users and user options are mutually exclusive"));
        }
        (Some(usernames), None) => {
            if usernames.len() > 1 {
                return Err(anyhow!("Multiple users are not supported"));
            }
            if usernames[0] != "default" {
                return Err(anyhow!("Only the 'default' user is supported"));
            }
            "Admin".into()
        }
        (None, Some(username)) => username.clone(),
        (None, None) => {
            return Err(anyhow!("Either users or user must be specified"));
        }
    };

    // Create user if it doesn't exist
    info!("Creating user: {user}");
    util::run_powershell_command(&format!(
        r#"if (!(Get-LocalUser -Name "{user}" -ErrorAction SilentlyContinue)) {{
            New-LocalUser -Name "{user}" -NoPassword
        }}"#
    ))
    .map_err(|e| anyhow!("Failed to create user {user} if it doesn't exist: {e}"))?;

    if let Some(password) = &user_data.password.expose_secret() {
        info!("Updating {user} password");

        if let Err(e) = set_user_password(&user, password, user_data.chpasswd.expire) {
            error!("Failed to set password for user {user}: {e}");
        }
    }

    // Add user to administrators group if it's not already a member
    if let Err(e) = util::run_powershell_command(&format!(
        r#"if (!(Get-LocalGroupMember -Group "Administrators" -Member "{user}" -ErrorAction SilentlyContinue)) {{
            Add-LocalGroupMember -Group "Administrators" -Member "{user}"
        }}"#
    )) {
        error!("Failed to add user {user} to Administrators group: {e}");
    }

    if let Err(e) = handle_ssh_keys(&user_data.ssh_authorized_keys) {
        error!("Failed to handle SSH authorized keys: {e}");
    }

    if user_data.manage_etc_hosts {
        warn!("manage_etc_hosts is not supported");
    }

    if user_data.package_upgrade {
        warn!("package_upgrade is not supported");
    }

    Ok(())
}
