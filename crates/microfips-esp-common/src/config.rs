// Build-time override: FIPS_TARGET_HOST selects the FIPS daemon the firmware
// connects to (hostname or IPv4 literal). Defaults to the VPS.
pub const VPS_HOST: &str = match option_env!("FIPS_TARGET_HOST") {
    Some(v) => v,
    None => "orangeclaw.dns4sats.xyz",
};
pub const VPS_PORT: u16 = 2121;
pub const WIFI_DHCP_TIMEOUT_SECS: u64 = 30;
pub const DNS_TIMEOUT_SECS: u64 = 5;
pub const DNS_PORT: u16 = 53;
pub const DNS_QUERY_ID: u16 = 0x4D46;
