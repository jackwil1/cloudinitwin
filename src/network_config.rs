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
                warn!("Unparsed content remaining: {}", remainder);
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
        Err(e) => Err(anyhow!("Failed to parse network config: {}", e)),
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

pub fn handle_network_config(network_config: NetworkConfig) -> anyhow::Result<()> {
    fn netmask_to_prefix(netmask: IpAddr) -> anyhow::Result<u8> {
        match netmask {
            IpAddr::V4(mask) => {
                let mask_u32 = u32::from(mask);
                if (!mask_u32).wrapping_add(1).is_power_of_two() || mask_u32 == u32::MAX {
                    Ok(mask_u32.count_ones() as u8)
                } else {
                    Err(anyhow!("Invalid netmask: {}", mask))
                }
            }
            IpAddr::V6(_) => Err(anyhow!("IPv6 is not supported yet")),
        }
    }

    let adaptor_indices = util::run_powershell_command(
        r#"Get-NetAdapter -Physical | Where-Object { $_.Name -like "Ethernet*" } | Sort-Object InterfaceIndex | Select-Object -ExpandProperty InterfaceIndex"#,
    )
    .map_err(|e| anyhow!("Failed to get network adaptor indices: {e}",))?
    .lines()
    .filter_map(|line| line.trim().parse::<u32>().ok())
    .collect::<Vec<_>>();

    for (iface_num, config) in network_config {
        info!("Configuring interface eth{}: {:?}", iface_num, config);

        let iface_num_usize = iface_num as usize;
        if iface_num_usize >= adaptor_indices.len() {
            return Err(anyhow!(
                "Interface eth{} not found. Only {} physical interfaces detected.",
                iface_num,
                adaptor_indices.len()
            ));
        }
        let interface_index = adaptor_indices[iface_num_usize];

        match config.mode {
            InterfaceMode::Dhcp => {
                util::run_powershell_command(&format!(
                    "Get-NetIPAddress -InterfaceIndex {0} | Remove-NetIPAddress -Confirm:$false; Set-NetIPInterface -InterfaceIndex {0} -Dhcp Enabled",
                    interface_index
                ))?;
            }
            InterfaceMode::Static => {
                let address = config
                    .address
                    .ok_or_else(|| anyhow!("Static config for eth{iface_num} missing address"))?;
                let netmask = config
                    .netmask
                    .ok_or_else(|| anyhow!("Static config for eth{iface_num} missing netmask"))?;
                let gateway = config.gateway.ok_or_else(|| {
                    anyhow!("Static config for eth{iface_num} missing default gateway")
                })?;
                let prefix_length = netmask_to_prefix(netmask)?;

                util::run_powershell_command(&format!(
                    r#"
                    Set-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv6 -RouterDiscovery Disabled -Dhcp Disabled;
                    Set-NetIPInterface -InterfaceIndex {interface_index} -AddressFamily IPv4 -Dhcp Disabled;
                    Get-NetIPAddress -InterfaceIndex {interface_index} | Remove-NetIPAddress -Confirm:$false;
                    Remove-NetRoute -InterfaceIndex {interface_index} -Confirm:$false;
                    New-NetIPAddress -InterfaceIndex {interface_index} -IPAddress '{address}' -PrefixLength {prefix_length} -DefaultGateway '{gateway}';
                    Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ServerAddresses @('{gateway}')
                    "#
                ))?;

                std::thread::sleep(std::time::Duration::from_secs(1));

                // Wait for internet connectivity
                if !wait_for_internet_connection(std::time::Duration::from_secs(30)) {
                    warn!("Failed to connect to internet");
                }
            }
        }
    }
    Ok(())
}
