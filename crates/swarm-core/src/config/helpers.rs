use super::*;

pub(super) fn validate_json_pointer(
    field: &'static str,
    pointer: &str,
) -> Result<(), ConfigValidationError> {
    if pointer.trim().is_empty() {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    if !pointer.starts_with('/') {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be a JSON Pointer starting with `/`".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_percentage_threshold(
    field: &'static str,
    value: f64,
) -> Result<(), ConfigValidationError> {
    if !(0.0..=100.0).contains(&value) || value == 0.0 {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be greater than 0.0 and less than or equal to 100.0".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_non_empty(
    field: &'static str,
    value: &str,
) -> Result<(), ConfigValidationError> {
    if value.trim().is_empty() {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must not be empty".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_timeout(
    field: &'static str,
    value: u64,
) -> Result<(), ConfigValidationError> {
    if value == 0 {
        return Err(ConfigValidationError::InvalidField {
            field,
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_retry_config(
    field_prefix: &'static str,
    retry: &RetryConfig,
) -> Result<(), ConfigValidationError> {
    if retry.initial_backoff_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "initial_backoff_ms must be greater than zero".to_string(),
        });
    }
    if retry.backoff_multiplier < 1.0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "backoff_multiplier must be at least 1.0".to_string(),
        });
    }
    Ok(())
}

pub(super) fn validate_circuit_breaker_config(
    field_prefix: &'static str,
    circuit_breaker: &CircuitBreakerConfig,
) -> Result<(), ConfigValidationError> {
    if circuit_breaker.threshold == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "threshold must be greater than zero".to_string(),
        });
    }
    if circuit_breaker.cooldown_ms == 0 {
        return Err(ConfigValidationError::InvalidField {
            field: field_prefix,
            reason: "cooldown_ms must be greater than zero".to_string(),
        });
    }
    Ok(())
}
