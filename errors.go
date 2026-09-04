package ironeye

import (
	"errors"
	"fmt"
)

// Error is the shape the server sends on every refusal.
//
// Retryable is the server's own verdict rather than an inference from the
// status code: a 429 from a spent monthly allowance is not the same wait as a
// 429 from a rate limiter, and only the body tells them apart.
type Error struct {
	Status          int            `json:"-"`
	Code            string         `json:"code"`
	Message         string         `json:"message"`
	Retryable       bool           `json:"retryable"`
	RequestID       string         `json:"request_id"`
	SuggestedAction string         `json:"suggested_action"`
	Doc             string         `json:"doc"`
	Path            string         `json:"path,omitempty"`
	Meta            map[string]any `json:"meta,omitempty"`
}

func (e *Error) Error() string {
	return fmt.Sprintf("ironeye: %s: %s (request_id=%s)", e.Code, e.Message, e.RequestID)
}

// Sentinels for errors.Is. Every one of them matches on the code, so a caller
// switches on the meaning rather than on a status number shared by four
// unrelated refusals.
var (
	ErrUnauthenticated = errors.New("ironeye: unauthenticated")
	ErrForbidden       = errors.New("ironeye: forbidden")
	ErrRateLimited     = errors.New("ironeye: rate limited")
	ErrInvalidRequest  = errors.New("ironeye: invalid request")
	ErrNotFound        = errors.New("ironeye: not found")
	ErrCompliance      = errors.New("ironeye: refused on compliance grounds")
	ErrUpstream        = errors.New("ironeye: upstream source failed")
	ErrServer          = errors.New("ironeye: server error")
)

var families = map[string]error{
	"UNAUTHENTICATED":       ErrUnauthenticated,
	"FORBIDDEN_SCOPE":       ErrForbidden,
	"PLAN_LIMITED":          ErrForbidden,
	"RATE_LIMITED":          ErrRateLimited,
	"QUOTA_EXHAUSTED":       ErrRateLimited,
	"TENANT_BUSY":           ErrRateLimited,
	"NOT_FOUND":             ErrNotFound,
	"COMPLIANCE_REFUSED":    ErrCompliance,
	"COLLECTION_BLOCKED":    ErrCompliance,
	"SOURCE_NOT_CONFIGURED": ErrUpstream,
	"UPSTREAM_REFUSED":      ErrUpstream,
	"UPSTREAM_THROTTLED":    ErrUpstream,
	"INTERNAL":              ErrServer,
	"DEPENDENCY_UNAVAILABLE": ErrServer,
	"SERVER_DRAINING":        ErrServer,
}

// Unwrap lets errors.Is(err, ErrRateLimited) work without the caller ever
// naming a status code.
func (e *Error) Unwrap() error {
	if family, ok := families[e.Code]; ok {
		return family
	}
	return ErrInvalidRequest
}

// AsError pulls the typed error out of anything this package returned.
func AsError(err error) (*Error, bool) {
	var target *Error
	ok := errors.As(err, &target)
	return target, ok
}
