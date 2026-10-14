use std::time::{SystemTime, UNIX_EPOCH};

/// Milliseconds since the Unix epoch; 0 if the clock is before the epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn now_is_after_2026() {
        assert!(super::now_ms() > 1_767_225_600_000);
    }
}
