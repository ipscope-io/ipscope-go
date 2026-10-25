package ipscope

import (
	"fmt"
	"time"
)

// ErrorCode identifies the category of an SDK error.
type ErrorCode string

const (
	ErrCodeValidation       ErrorCode = "IPSCOPE_VALIDATION_ERROR"
	ErrCodeTimeout          ErrorCode = "IPSCOPE_TIMEOUT_ERROR"
	ErrCodeNetwork          ErrorCode = "IPSCOPE_NETWORK_ERROR"
	ErrCodeUnauthorized     ErrorCode = "IPSCOPE_UNAUTHORIZED"
	ErrCodeForbiddenScope   ErrorCode = "IPSCOPE_FORBIDDEN_SCOPE"
	ErrCodeRateLimited      ErrorCode = "IPSCOPE_RATE_LIMITED"
	ErrCodeResponseTooLarge ErrorCode = "IPSCOPE_RESPONSE_TOO_LARGE"
	ErrCodeRetryExhausted   ErrorCode = "IPSCOPE_RETRY_EXHAUSTED"
)

// ValidationError is returned when client-side validation fails before any network call.
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("ipscope validation error (%s): %s", e.Field, e.Message)
	}
	return fmt.Sprintf("ipscope validation error: %s", e.Message)
}

// TimeoutError is returned when an HTTP request exceeds the configured timeout or context deadline.
type TimeoutError struct {
	Path    string
	Timeout time.Duration
	Cause   error
}

func (e *TimeoutError) Error() string {
	if e.Timeout > 0 {
		return fmt.Sprintf("ipscope request to %q timed out after %s", e.Path, e.Timeout)
	}
	return fmt.Sprintf("ipscope request to %q timed out", e.Path)
}

func (e *TimeoutError) Unwrap() error {
	return e.Cause
}

// APIError is returned when the IPScope API responds with a non-2xx status or transport failure.
type APIError struct {
	Message    string
	Code       ErrorCode
	Status     int
	Path       string
	RateLimit  *RateLimitMetadata
	RetryAfter time.Duration
	Cause      error
}

func (e *APIError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("ipscope api error (%d %s) on %s: %s", e.Status, e.Code, e.Path, e.Message)
	}
	return fmt.Sprintf("ipscope api error (%s) on %s: %s", e.Code, e.Path, e.Message)
}

func (e *APIError) Unwrap() error {
	return e.Cause
}

// IsAuthError reports whether err is a 401 Unauthorized or 403 Forbidden APIError.
func IsAuthError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Status == 401 || apiErr.Status == 403
	}
	return false
}

// IsRateLimitError reports whether err is a 429 Too Many Requests APIError.
func IsRateLimitError(err error) bool {
	if apiErr, ok := err.(*APIError); ok {
		return apiErr.Status == 429 || apiErr.Code == ErrCodeRateLimited
	}
	return false
}

// IsTimeoutError reports whether err is a TimeoutError.
func IsTimeoutError(err error) bool {
	_, ok := err.(*TimeoutError)
	return ok
}

// IsValidationError reports whether err is a ValidationError.
func IsValidationError(err error) bool {
	_, ok := err.(*ValidationError)
	return ok
}
