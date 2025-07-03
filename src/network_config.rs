use std::collections::HashMap;
use std::ffi::OsString;
use std::net::IpAddr;
use std::path::PathBuf;
use std::str::FromStr;

use log::{debug, info, warn};
use nom::IResult;
use nom::Parser;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::character::complete::digit1;
use nom::combinator::{map_res, recognize, value};
use nom::multi::{many0, many1};

use anyhow::anyhow;

use crate::util;

#[derive(Clone, Debug)]
pub enum InterfaceMode {
    Static,
    Dhcp,
}

#[derive(Debug)]
pub struct InterfaceConfig {
    iface: u8,
    mode: InterfaceMode,
    address: Option<IpAddr>,
    netmask: Option<IpAddr>,
    gateway: Option<IpAddr>,
}

#[derive(Debug)]
pub enum Stanza {
    Auto,
    Iface(InterfaceConfig),
}

fn whitespace0(input: &str) -> IResult<&str, &str> {
    take_while(|c| c == ' ' || c == '\t')(input)
}

fn whitespace1(input: &str) -> IResult<&str, &str> {
    take_while1(|c| c == ' ' || c == '\t')(input)
}

fn whitespace_newline1(input: &str) -> IResult<&str, &str> {
    let (remainder, _) = whitespace0(input)?;
    take_while1(|c| c == '\n' || c == '\r')(remainder)
}

fn whitespace_newlines1(input: &str) -> IResult<&str, &str> {
    recognize(many1(whitespace_newline1)).parse(input)
}

fn parse_ip_address(input: &str) -> IResult<&str, IpAddr> {
    map_res(take_while1(|c: char| !c.is_whitespace()), IpAddr::from_str).parse(input)
}

#[derive(Debug)]
#[allow(dead_code)]
enum IfaceOption {
    Address(IpAddr),
    Netmask(IpAddr),
    Gateway(IpAddr),
    DnsNameservers(IpAddr),
}
fn parse_iface_option(input: &str) -> IResult<&str, IfaceOption> {
    let (remainder, _) = whitespace1(input)?;
    let (remainder, key) = alt((
        tag("address"),
        tag("netmask"),
        tag("gateway"),
        tag("dns-nameservers"),
    ))
    .parse(remainder)?;
    let (remainder, _) = whitespace1(remainder)?;
    let (remainder, ip) = parse_ip_address(remainder)?;
    let (remainder, _) = whitespace_newlines1(remainder)?;

    let option = match key {
        "address" => IfaceOption::Address(ip),
        "netmask" => IfaceOption::Netmask(ip),
        "gateway" => IfaceOption::Gateway(ip),
        "dns-nameservers" => IfaceOption::DnsNameservers(ip),
        _ => unreachable!(),
    };

    Ok((remainder, option))
}

fn parse_auto(input: &str) -> IResult<&str, Stanza> {
    let (remainder, _) = tag("auto")(input)?;
    let (remainder, _) = whitespace1(remainder)?;
    let (remainder, _) = take_while1(|c: char| !c.is_whitespace())(remainder)?; // consume interface name
    let (remainder, _) = whitespace_newlines1(remainder)?;
    Ok((remainder, Stanza::Auto))
}

fn parse_iface(input: &str) -> IResult<&str, Stanza> {
    let (remainder, _) = tag("iface")(input)?;
    let (remainder, _) = whitespace1(remainder)?;
    let (remainder, _) = tag("eth")(remainder)?;
    let (remainder, iface_num) = map_res(digit1, |s: &str| s.parse::<u8>()).parse(remainder)?;
    let (remainder, _) = whitespace1(remainder)?;
    let (remainder, _) = tag("inet")(remainder)?;
    let (remainder, _) = whitespace1(remainder)?;
    let (remainder, mode) = alt((
        value(InterfaceMode::Static, tag("static")),
        value(InterfaceMode::Dhcp, tag("dhcp")),
    ))
    .parse(remainder)?;
    let (remainder, _) = whitespace_newlines1(remainder)?;

    let (remainder, options) = many0(parse_iface_option).parse(remainder)?;

    let mut config = InterfaceConfig {
        iface: iface_num,
        mode,
        address: None,
        netmask: None,
        gateway: None,
    };

    for option in options {
        match option {
            IfaceOption::Address(ip) => config.address = Some(ip),
            IfaceOption::Netmask(ip) => config.netmask = Some(ip),
            IfaceOption::Gateway(ip) => config.gateway = Some(ip),
            IfaceOption::DnsNameservers(_) => {
                warn!("Ignoring DNS nameservers, which is not a valid configuration option")
            }
        }
    }

    Ok((remainder, Stanza::Iface(config)))
}

fn parse_stanza(input: &str) -> IResult<&str, Stanza> {
    alt((parse_auto, parse_iface)).parse(input)
}

type NetworkConfig = HashMap<u8, InterfaceConfig>;

fn parse_network_config_inner(contents: &str) -> anyhow::Result<NetworkConfig> {
    match many1(parse_stanza).parse(contents) {
        Ok((remainder, stanzas)) => {
            if !remainder.is_empty() {
                warn!("Unparsed content remaining: {remainder}");
            }
            let mut intefaces_map = NetworkConfig::new();
            for stanza in stanzas {
                match stanza {
                    Stanza::Auto => {
                        // Auto stanza does not require any action
                    }
                    Stanza::Iface(config) => {
                        if intefaces_map.contains_key(&config.iface) {
                            return Err(anyhow!(
                                "Duplicate interface configuration for iface {}",
                                config.iface
                            ));
                        }
                        intefaces_map.insert(config.iface, config);
                    }
                }
            }

            Ok(intefaces_map)
        }
        Err(e) => Err(anyhow!("Failed to parse network config: {e}")),
    }
}

pub fn parse_network_config(
    network_config_path: &str,
    config_drive: &OsString,
) -> anyhow::Result<NetworkConfig> {
    let network_config_path_safe = network_config_path.trim_start_matches(&['/', '\\']);
    let network_config_full_path: PathBuf = [
        config_drive,
        &OsString::from("openstack"),
        &OsString::from(network_config_path_safe),
    ]
    .into_iter()
    .collect::<PathBuf>();

    debug!(
        "Network config path: {}",
        network_config_full_path.to_string_lossy()
    );

    let contents = std::fs::read_to_string(&network_config_full_path)
        .map_err(|e| anyhow!("Failed to read network config file: {e}"))?;

    parse_network_config_inner(&contents)
}

fn wait_for_internet_connection(timeout: std::time::Duration) -> bool {
    const TEST_HOST: &str = "8.8.8.8";

    let end_time = std::time::Instant::now() + timeout;

    while std::time::Instant::now() < end_time {
        if std::net::TcpStream::connect((TEST_HOST, 53)).is_ok() {
            info!("Connected to internet successfully.");
            return true;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    return false;
}

fn netmask_to_prefix(netmask: IpAddr) -> anyhow::Result<u8> {
    match netmask {
        IpAddr::V4(mask) => {
            let mask_u32 = u32::from(mask);
            if (!mask_u32).wrapping_add(1).is_power_of_two() || mask_u32 == u32::MAX {
                Ok(mask_u32.count_ones() as u8)
            } else {
                Err(anyhow!("Invalid netmask: {mask}"))
            }
        }
        IpAddr::V6(_) => Err(anyhow!("IPv6 is not supported yet")),
    }
}

fn get_current_dns_servers(interface_index: u32) -> anyhow::Result<Vec<IpAddr>> {
    let output = util::run_powershell_command(&format!(
        "Get-DnsClientServerAddress -InterfaceIndex {interface_index} -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses"
    ))?;

    Ok(output
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .filter_map(|l| IpAddr::from_str(l).ok())
        .collect::<Vec<_>>())
}

fn is_dhcp_enabled(interface_index: u32) -> anyhow::Result<bool> {
    let output = util::run_powershell_command(&format!(
        "Get-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv4 | Select-Object -ExpandProperty Dhcp"
    ))?;

    Ok(output.trim().eq_ignore_ascii_case("enabled"))
}

fn get_current_ip_config(interface_index: u32) -> anyhow::Result<(IpAddr, u8, IpAddr)> {
    // Get current IP address and prefix length
    let ip_output = util::run_powershell_command(&format!(
        "Get-NetIPAddress -InterfaceIndex {interface_index} -AddressFamily IPv4 | Select-Object IPAddress,PrefixLength | ConvertTo-Json"
    ))?;

    // Parse JSON output to extract IP and prefix length
    let ip_info: serde_json::Value = serde_json::from_str(&ip_output)
        .map_err(|e| anyhow!("Failed to parse IP address JSON: {e}"))?;

    let ip_addr = ip_info
        .get("IPAddress")
        .and_then(|v| v.as_str())
        .and_then(|s| IpAddr::from_str(s).ok())
        .ok_or_else(|| anyhow!("Missing or invalid IPAddress in response"))?;

    let prefix_length = ip_info
        .get("PrefixLength")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("Missing or invalid PrefixLength in response"))?
        as u8;

    // Get current default gateway
    let gateway_output = util::run_powershell_command(&format!(
        "Get-NetRoute -InterfaceIndex {interface_index} -DestinationPrefix '0.0.0.0/0' | Select-Object -ExpandProperty NextHop"
    ))?;

    let gateway = IpAddr::from_str(gateway_output.trim())
        .map_err(|e| anyhow!("Invalid gateway address: {e}"))?;

    Ok((ip_addr, prefix_length, gateway))
}

fn handle_network_interface(
    iface_num: u8,
    config: &InterfaceConfig,
    adaptor_indices: &Vec<u32>,
) -> anyhow::Result<()> {
    let interface_index = *adaptor_indices
        .get(iface_num as usize)
        .ok_or_else(|| anyhow!("Interface eth{iface_num} not found"))?;

    match config.mode {
        InterfaceMode::Dhcp => {
            let needs_dhcp_reconfig = match is_dhcp_enabled(interface_index) {
                Ok(true) => false,
                Ok(false) => {
                    info!("DHCP disabled -> reconfig");
                    true
                }
                Err(e) => {
                    warn!("DHCP check failed -> reconfig: {e}");
                    true
                }
            };

            if needs_dhcp_reconfig {
                info!("Reconfiguring DHCP");
                // Remove existing IP addresses first
                if let Err(e) = util::run_powershell_command(&format!(
                    "Get-NetIPAddress -InterfaceIndex {interface_index} -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false"
                )) {
                    warn!("Failed to remove existing IP addresses: {e}");
                }

                // Enable DHCP
                util::run_powershell_command(&format!(
                    "Set-NetIPInterface -InterfaceIndex {interface_index} -Dhcp Enabled"
                ))?;
            }
        }
        InterfaceMode::Static => {
            let address = config
                .address
                .ok_or_else(|| anyhow!("Static config missing address"))?;
            let netmask = config
                .netmask
                .ok_or_else(|| anyhow!("Static config missing netmask"))?;
            let gateway = config
                .gateway
                .ok_or_else(|| anyhow!("Static config missing default gateway"))?;
            let prefix_length = netmask_to_prefix(netmask)?;

            let needs_ip_reconfig = match get_current_ip_config(interface_index) {
                Ok(current_config) if current_config != (address, prefix_length, gateway) => {
                    info!("IP config differs -> reconfig: {current_config:?}");
                    true
                }
                Ok(_) => false,
                Err(e) => {
                    warn!("IP config check failed -> reconfig: {e}");
                    true
                }
            };
            let needs_dhcp_reconfig = match is_dhcp_enabled(interface_index) {
                Ok(true) => {
                    info!("DHCP enabled -> reconfig");
                    true
                }
                Ok(false) => false,
                Err(e) => {
                    warn!("DHCP check failed -> reconfig: {e}");
                    true
                }
            };

            if needs_ip_reconfig || needs_dhcp_reconfig {
                info!("Reconfiguring IP config");

                // Step 1: Disable DHCP and IPv6 router discovery
                util::run_powershell_command(&format!(
                    "Set-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv6 -RouterDiscovery Disabled -Dhcp Disabled"
                ))?;

                util::run_powershell_command(&format!(
                    "Set-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv4 -Dhcp Disabled"
                ))?;

                // Step 2: Remove existing IP addresses (ignore errors for non-existent addresses)
                if let Err(e) = util::run_powershell_command(&format!(
                    "Get-NetIPAddress -InterfaceIndex {interface_index} -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false"
                )) {
                    debug!("No existing IP addresses to remove: {e}");
                }

                // Step 3: Remove existing routes (ignore errors for non-existent routes)
                if let Err(e) = util::run_powershell_command(&format!(
                    "Get-NetRoute -InterfaceIndex {interface_index} | Remove-NetRoute -Confirm:$false"
                )) {
                    debug!("No existing routes to remove: {e}");
                }

                // Step 4: Add new IP address with gateway
                util::run_powershell_command(&format!(
                    "New-NetIPAddress -InterfaceIndex {interface_index} -IPAddress '{address}' -PrefixLength {prefix_length} -DefaultGateway '{gateway}'"
                ))?;
            }

            if match get_current_dns_servers(interface_index) {
                Ok(current_dns_servers)
                    if current_dns_servers.is_empty()
                        || current_dns_servers.len() != 1
                        || current_dns_servers[0] != gateway =>
                {
                    info!("DNS servers differ -> reconfig: {current_dns_servers:?}");
                    true
                }
                Ok(_) => false,
                Err(e) => {
                    warn!("DNS server check failed -> reconfig: {e}");
                    true
                }
            } {
                info!("Reconfiguring DNS servers");
                util::run_powershell_command(&format!(
                    "Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ServerAddresses @('{gateway}')"
                ))?;
            }
        }
    }

    Ok(())
}

pub fn handle_network_config(network_config: NetworkConfig) -> anyhow::Result<()> {
    let adaptor_indices = util::run_powershell_command(
        r#"Get-NetAdapter -Physical | Where-Object { $_.Name -like "Ethernet*" } | Sort-Object InterfaceIndex | Select-Object -ExpandProperty InterfaceIndex"#,
    )
    .map_err(|e| anyhow!("Failed to get network adaptor indices: {e}"))?
    .lines()
    .filter_map(|line| line.trim().parse::<u32>().ok())
    .collect::<Vec<_>>();

    for (iface_num, config) in network_config {
        info!("Configuring interface eth{iface_num}: {config:?}");

        if let Err(e) = handle_network_interface(iface_num, &config, &adaptor_indices) {
            warn!("Failed to configure interface eth{iface_num}: {e}");
        } else {
            info!("Interface eth{iface_num} configured successfully");
        }
    }

    // Wait for internet connectivity
    if !wait_for_internet_connection(std::time::Duration::from_secs(30)) {
        warn!("Failed to connect to internet");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::netmask_to_prefix;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_valid_netmasks() {
        let cases = vec![
            ("255.0.0.0", 8),
            ("255.255.0.0", 16),
            ("255.255.255.0", 24),
            ("255.255.255.128", 25),
            ("255.255.255.192", 26),
            ("255.255.255.224", 27),
            ("255.255.255.240", 28),
            ("255.255.255.248", 29),
            ("255.255.255.252", 30),
            ("255.255.255.254", 31),
            ("255.255.255.255", 32),
        ];
        for (mask, expected) in cases {
            let ip = IpAddr::from_str(mask).unwrap();
            let prefix = netmask_to_prefix(ip).unwrap();
            assert_eq!(prefix, expected, "netmask {} should be /{}", mask, expected);
        }
    }

    #[test]
    fn test_invalid_netmasks() {
        let cases = vec!["255.0.255.0", "255.255.128.255", "255.255.255.1", "0.0.0.0"];
        for mask in cases {
            let ip = IpAddr::from_str(mask).unwrap();
            assert!(
                netmask_to_prefix(ip).is_err(),
                "netmask {} should be invalid",
                mask
            );
        }
    }

    #[test]
    fn test_ipv6_not_supported() {
        let ip = IpAddr::from_str("ffff:ffff:ffff:ffff::").unwrap();
        assert!(netmask_to_prefix(ip).is_err());
    }
}
