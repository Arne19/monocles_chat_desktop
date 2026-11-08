//! Tor (`.onion`) and I2P (`.i2p`) names. This client has no Tor/I2P support, so such a name can
//! never be reached - and it must never be sent to a DNS server either: that would only leak the
//! hidden service's address to the resolver (and anyone watching the network). Every place that
//! resolves a remote-supplied or user-supplied host refuses them up front. Same rule as Android's
//! `HttpConnectionManager.isOnionHost/isI2PHost`.

/// Whether `host` is a `.onion` or `.i2p` name (case-insensitive, trailing dots ignored).
pub fn is_hidden_service_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host.ends_with(".onion") || host.ends_with(".i2p")
}

#[cfg(test)]
mod tests {
    use super::is_hidden_service_host;

    #[test]
    fn hidden_service_names_are_recognised() {
        for hidden in ["abc.onion", "ABC.ONION", "abc.onion.", "a.b.onion..", "site.i2p", "x.I2P."] {
            assert!(is_hidden_service_host(hidden), "{hidden}");
        }
        for clearnet in ["", "onion", "i2p", "notonion.com", "onion.example", "example.org", "9.9.9.9", "::1"] {
            assert!(!is_hidden_service_host(clearnet), "{clearnet}");
        }
    }
}
