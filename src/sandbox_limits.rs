//! Operator usage ceilings. Zero disables enforcement while measurements remain
//! enabled. Configuration is validated once before serving requests; request
//! handlers never read environment variables or infer a limit from capacity.

use std::sync::OnceLock;

macro_rules! limits {
    ($($field:ident => $env:literal),+ $(,)?) => {
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct SandboxLimits { $(pub $field: u64),+ }
        impl SandboxLimits {
            pub fn from_lookup(mut lookup: impl FnMut(&str) -> anyhow::Result<Option<String>>) -> anyhow::Result<Self> {
                Ok(Self { $($field: parse($env, lookup($env)?.as_deref())?),+ })
            }
            fn publish(&self) {
                $(crate::metrics::SANDBOX_USAGE_LIMIT.with_label_values(&[stringify!($field)]).set(self.$field as f64);)+
            }
        }
    }
}
limits! {
    stream_bytes => "KOBE_SANDBOX_STREAM_MAX_BYTES",
    stream_idle_seconds => "KOBE_SANDBOX_STREAM_IDLE_SECONDS",
    stream_duration_seconds => "KOBE_SANDBOX_STREAM_DURATION_SECONDS",
    executions_per_lease => "KOBE_SANDBOX_MAX_EXECUTIONS_PER_LEASE",
    streams_per_lease => "KOBE_SANDBOX_MAX_STREAMS_PER_LEASE",
    streams_per_principal => "KOBE_SANDBOX_MAX_STREAMS_PER_PRINCIPAL",
    output_bytes => "KOBE_SANDBOX_OUTPUT_MAX_BYTES",
    stdin_bytes => "KOBE_SANDBOX_STDIN_MAX_BYTES",
    log_tail_lines => "KOBE_SANDBOX_LOG_MAX_LINES",
    legacy_exec_seconds => "KOBE_SANDBOX_LEGACY_EXEC_SECONDS",
    admission_burst => "KOBE_SANDBOX_ADMISSION_BURST",
}

static CONFIG: OnceLock<SandboxLimits> = OnceLock::new();
static DEFAULT: SandboxLimits = SandboxLimits {
    stream_bytes: 0,
    stream_idle_seconds: 0,
    stream_duration_seconds: 0,
    executions_per_lease: 0,
    streams_per_lease: 0,
    streams_per_principal: 0,
    output_bytes: 0,
    stdin_bytes: 0,
    log_tail_lines: 0,
    legacy_exec_seconds: 0,
    admission_burst: 0,
};

/// Called before starting the operator. Invalid values fail startup.
pub fn initialize() -> anyhow::Result<()> {
    let limits = SandboxLimits::from_lookup(|name| match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => anyhow::bail!("invalid {name}: {error}"),
    })?;
    limits.publish();
    CONFIG
        .set(limits)
        .map_err(|_| anyhow::anyhow!("Sandbox limits already initialized"))
}

pub fn get() -> &'static SandboxLimits {
    CONFIG.get().unwrap_or(&DEFAULT)
}

fn parse(name: &str, value: Option<&str>) -> anyhow::Result<u64> {
    let Some(value) = value else { return Ok(0) };
    anyhow::ensure!(
        !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()),
        "{name} must be a non-negative integer; 0 disables the limit"
    );
    value
        .parse()
        .map_err(|_| anyhow::anyhow!("{name} exceeds the supported integer range"))
}

/// Record an observation even when enforcement is disabled. Labels are a closed
/// set of resource names; no principal, lease ID, command or content is exported.
pub fn observe(resource: &'static str, value: u64) {
    crate::metrics::SANDBOX_USAGE_OBSERVED
        .with_label_values(&[resource])
        .observe(value as f64);
}

pub fn exceeds(resource: &'static str, value: u64, limit: u64) -> bool {
    observe(resource, value);
    if limit != 0 && value > limit {
        crate::metrics::SANDBOX_USAGE_REJECTED
            .with_label_values(&[resource])
            .inc();
        true
    } else {
        false
    }
}

/// Convert an optional byte/count ceiling for APIs accepting `usize`.
pub fn capacity(value: u64) -> usize {
    if value == 0 {
        usize::MAX
    } else {
        usize::try_from(value).unwrap_or(usize::MAX)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_usage_ceiling_is_disabled_by_default() {
        let defaults = SandboxLimits::from_lookup(|_| Ok(None)).unwrap();
        assert_eq!(defaults, DEFAULT);
        let zero = SandboxLimits::from_lookup(|_| Ok(Some("0".into()))).unwrap();
        assert_eq!(zero, DEFAULT);
        assert!(!exceeds("stdin_bytes", 2 * 1024 * 1024, zero.stdin_bytes));
    }
    #[test]
    fn explicit_limits_are_enforced_and_malformed_values_are_rejected() {
        assert!(!exceeds("stdin_bytes", 16, 16));
        assert!(exceeds("stdin_bytes", 17, 16));
        for value in ["", "-1", "1.5", "1Mi", "18446744073709551616"] {
            assert!(SandboxLimits::from_lookup(|_| Ok(Some(value.into()))).is_err());
        }
    }
}
