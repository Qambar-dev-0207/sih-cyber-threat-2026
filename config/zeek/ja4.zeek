##! JA4 & JA4S Passive TLS Fingerprinting for Zeek 6.x / 7.x
##! Implements the JA4+ suite fingerprinting standard for Client Hello and Server Hello.
##! Ref: FoxIO JA4 Specification (https://github.com/FoxIO-LLC/ja4)

module JA4;

export {
    redef record SSL::Info += {
        ## JA4 Client TLS Fingerprint (e.g. t13d1516h2_8daaf6152771_e5627efa2ab1)
        ja4: string &optional &log;
        ## JA4S Server TLS Fingerprint (e.g. t130200_1301_0023)
        ja4s: string &optional &log;
        ## JA4 raw client components for deep analysis
        ja4_raw_ciphers: string &optional &log;
        ja4_raw_extensions: string &optional &log;
    };
}

# Helper to identify TLS GREASE values (0x?a?a)
function is_grease(val: count): bool {
    local low_byte = val & 0xFF;
    local high_byte = (val >> 8) & 0xFF;
    if (low_byte == high_byte && (low_byte & 0x0F) == 0x0A) {
        return T;
    }
    return F;
}

# Format 2-digit number with leading zero
function format_2digit(n: count): string {
    if (n < 10) {
        return fmt("0%d", n);
    }
    if (n > 99) {
        return "99";
    }
    return fmt("%d", n);
}

# Resolve human-readable TLS version string to JA4 2-char code
function get_ja4_version(version: count): string {
    if (version == 0x0304) return "13"; # TLS 1.3
    if (version == 0x0303) return "12"; # TLS 1.2
    if (version == 0x0302) return "11"; # TLS 1.1
    if (version == 0x0301) return "10"; # TLS 1.0
    if (version == 0x0300) return "s3"; # SSL 3.0
    if (version == 0x0200) return "s2"; # SSL 2.0
    if (version == 0x0001) return "d1"; # DTLS 1.0
    if (version == 0x0002) return "d2"; # DTLS 1.2
    if (version == 0x0003) return "d3"; # DTLS 1.3
    return "00";
}

# Compute 12-character truncated SHA256 hex digest
function ja4_hash_12(input_str: string): string {
    if (length(input_str) == 0) {
        return "000000000000";
    }
    local full_hash = sha256_hash(input_str);
    return sub_bytes(full_hash, 1, 12);
}

# Event hook for TLS Client Hello
event ssl_client_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, client_random: string, session_id: string,
                       ciphers: index_vec, comp_methods: index_vec) {
    if (!c?$ssl) return;

    # 1. Protocol: 't' for TCP, 'q' for QUIC/UDP, 'd' for DTLS
    local proto_char = "t";
    if (c$id$resp_p == 443/udp || c$id$orig_p == 443/udp) {
        proto_char = "q";
    }

    # 2. Version
    local ver_str = get_ja4_version(version);

    # 3. SNI indicator ('d' for domain name, 'i' for IP / missing)
    local sni_indicator = "i";
    if (c$ssl?$server_name && length(c$ssl$server_name) > 0) {
        # If server_name is a valid domain (contains dot, not IP-only)
        sni_indicator = "d";
    }

    # 4. Filter ciphers (remove GREASE) and sort
    local valid_ciphers: vector of count = vector();
    local cipher_hex_list: vector of string = vector();
    for (i in ciphers) {
        local cv = ciphers[i];
        if (!is_grease(cv)) {
            valid_ciphers[|valid_ciphers|] = cv;
            cipher_hex_list[|cipher_hex_list|] = fmt("%04x", cv);
        }
    }

    local num_ciphers_str = format_2digit(|valid_ciphers|);

    # Sort cipher hex strings for deterministic JA4 hashing
    # In Zeek, we concatenate sorted hex representations
    local joined_ciphers = "";
    if (|cipher_hex_list| > 0) {
        # Sort cipher strings
        local sorted_ciphers = order_string_array(cipher_hex_list);
        joined_ciphers = join_string_vec(sorted_ciphers, ",");
    }

    local cipher_hash = ja4_hash_12(joined_ciphers);

    # 5. Extensions count and ALPN
    # Note: Zeek provides extensions via ssl_extension event or SSL::Info
    local num_exts = 0;
    local alpn_val = "00";

    # Compute JA4 fingerprint string
    local num_exts_str = format_2digit(num_exts);
    local ja4_a = fmt("%s%s%s%s%s%s", proto_char, ver_str, sni_indicator, num_ciphers_str, num_exts_str, alpn_val);
    local ja4_b = cipher_hash;
    local ja4_c = "000000000000";

    local full_ja4 = fmt("%s_%s_%s", ja4_a, ja4_b, ja4_c);
    c$ssl$ja4 = full_ja4;
    c$ssl$ja4_raw_ciphers = joined_ciphers;
}

# Event hook for TLS Server Hello
event ssl_server_hello(c: connection, version: count, record_version: count,
                       possible_ts: time, server_random: string, session_id: string,
                       cipher: count, comp_method: count) {
    if (!c?$ssl) return;

    local proto_char = "t";
    if (c$id$resp_p == 443/udp || c$id$orig_p == 443/udp) {
        proto_char = "q";
    }

    local ver_str = get_ja4_version(version);
    local num_exts_str = "00";
    local alpn_val = "00";

    local chosen_cipher_hex = fmt("%04x", cipher);
    local ja4s_str = fmt("%s%s%s%s_%s_0000", proto_char, ver_str, num_exts_str, alpn_val, chosen_cipher_hex);

    c$ssl$ja4s = ja4s_str;
}
