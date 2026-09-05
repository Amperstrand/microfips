// Build-time override: FIPS_TARGET_HOST selects the FIPS daemon the firmware
// connects to (hostname or IPv4 literal). Defaults to the VPS.
pub const VPS_HOST: &str = match option_env!("FIPS_TARGET_HOST") {
    Some(v) => v,
    None => "orangeclaw.dns4sats.xyz",
};
// Build-time override: FIPS_TARGET_PORT (decimal u16). Defaults to 2121.
// Bench scenarios pin host+port to the lab daemon so the static fallback
// targets the scenario daemon itself instead of the VPS — pinned mDNS
// discovery stays the primary path, but a discovery miss no longer burns a
// 30 s cycle against an unreachable fallback (2026-09-05 soak-long nightly).
pub const VPS_PORT: u16 = parse_target_port(option_env!("FIPS_TARGET_PORT"));
pub const WIFI_DHCP_TIMEOUT_SECS: u64 = 30;
pub const DNS_TIMEOUT_SECS: u64 = 5;

const fn parse_target_port(v: Option<&str>) -> u16 {
    let Some(s) = v else {
        return 2121;
    };
    let bytes = s.as_bytes();
    let mut value = 0u32;
    let mut i = 0;
    while i < bytes.len() {
        assert!(
            bytes[i] >= b'0' && bytes[i] <= b'9',
            "FIPS_TARGET_PORT must be a decimal number"
        );
        value = value * 10 + (bytes[i] - b'0') as u32;
        i += 1;
    }
    assert!(value > 0 && value <= 65535, "FIPS_TARGET_PORT out of range");
    value as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_port_is_2121() {
        assert_eq!(parse_target_port(None), 2121);
    }

    #[test]
    fn parses_decimal_override() {
        assert_eq!(parse_target_port(Some("21213")), 21213);
        assert_eq!(parse_target_port(Some("1")), 1);
        assert_eq!(parse_target_port(Some("65535")), 65535);
    }

    #[test]
    #[should_panic(expected = "decimal")]
    fn rejects_non_numeric() {
        parse_target_port(Some("21a13"));
    }

    #[test]
    #[should_panic(expected = "range")]
    fn rejects_zero() {
        parse_target_port(Some("0"));
    }

    #[test]
    #[should_panic(expected = "range")]
    fn rejects_above_65535() {
        parse_target_port(Some("65536"));
    }
}
