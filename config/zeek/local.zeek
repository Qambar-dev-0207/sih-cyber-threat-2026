##! SIH26145 Zeek Master Site Configuration
##! Configured for real-time passive telemetry streaming to Redpanda/Kafka in a unidirectional data diode enclave.

@load base/frameworks/logging
@load policy/tuning/json-logs.zeek
@load policy/protocols/ssl/validate-certs.zeek
@load policy/protocols/ssl/log-host-certs-only.zeek
@load ./ja4.zeek

# =============================================================================
# Structured JSON Logging Configuration
# =============================================================================
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;
redef LogAscii::json_include_unset_fields = F;

# Disable periodic log rotation to maintain continuous append streams for file tailers & shippers
redef Log::default_rotation_interval = 0 sec;

# Community ID Hash generation for cross-tool flow correlation
@load policy/protocols/conn/community-id-logging.zeek

# =============================================================================
# Core Protocol Analyzers
# =============================================================================
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/http

# Optimize connection timeout and state tracking for line-rate monitoring
redef tcp_inactivity_timeout = 60 sec;
redef tcp_attempt_delay = 5 sec;
redef udp_inactivity_timeout = 30 sec;
