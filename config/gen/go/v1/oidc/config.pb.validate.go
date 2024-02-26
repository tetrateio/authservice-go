// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: v1/oidc/config.proto

package oidc

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on TokenConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *TokenConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on TokenConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in TokenConfigMultiError, or
// nil if none found.
func (m *TokenConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *TokenConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetHeader()) < 1 {
		err := TokenConfigValidationError{
			field:  "Header",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	// no validation rules for Preamble

	if len(errors) > 0 {
		return TokenConfigMultiError(errors)
	}

	return nil
}

// TokenConfigMultiError is an error wrapping multiple validation errors
// returned by TokenConfig.ValidateAll() if the designated constraints aren't met.
type TokenConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m TokenConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m TokenConfigMultiError) AllErrors() []error { return m }

// TokenConfigValidationError is the validation error returned by
// TokenConfig.Validate if the designated constraints aren't met.
type TokenConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e TokenConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e TokenConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e TokenConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e TokenConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e TokenConfigValidationError) ErrorName() string { return "TokenConfigValidationError" }

// Error satisfies the builtin error interface
func (e TokenConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sTokenConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = TokenConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = TokenConfigValidationError{}

// Validate checks the field values on RedisConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *RedisConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RedisConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in RedisConfigMultiError, or
// nil if none found.
func (m *RedisConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *RedisConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetServerUri()) < 1 {
		err := RedisConfigValidationError{
			field:  "ServerUri",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return RedisConfigMultiError(errors)
	}

	return nil
}

// RedisConfigMultiError is an error wrapping multiple validation errors
// returned by RedisConfig.ValidateAll() if the designated constraints aren't met.
type RedisConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RedisConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RedisConfigMultiError) AllErrors() []error { return m }

// RedisConfigValidationError is the validation error returned by
// RedisConfig.Validate if the designated constraints aren't met.
type RedisConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RedisConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RedisConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RedisConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RedisConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RedisConfigValidationError) ErrorName() string { return "RedisConfigValidationError" }

// Error satisfies the builtin error interface
func (e RedisConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRedisConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RedisConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RedisConfigValidationError{}

// Validate checks the field values on LogoutConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *LogoutConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on LogoutConfig with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in LogoutConfigMultiError, or
// nil if none found.
func (m *LogoutConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *LogoutConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if utf8.RuneCountInString(m.GetPath()) < 1 {
		err := LogoutConfigValidationError{
			field:  "Path",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetRedirectUri()) < 1 {
		err := LogoutConfigValidationError{
			field:  "RedirectUri",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return LogoutConfigMultiError(errors)
	}

	return nil
}

// LogoutConfigMultiError is an error wrapping multiple validation errors
// returned by LogoutConfig.ValidateAll() if the designated constraints aren't met.
type LogoutConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m LogoutConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m LogoutConfigMultiError) AllErrors() []error { return m }

// LogoutConfigValidationError is the validation error returned by
// LogoutConfig.Validate if the designated constraints aren't met.
type LogoutConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e LogoutConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e LogoutConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e LogoutConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e LogoutConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e LogoutConfigValidationError) ErrorName() string { return "LogoutConfigValidationError" }

// Error satisfies the builtin error interface
func (e LogoutConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sLogoutConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = LogoutConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = LogoutConfigValidationError{}

// Validate checks the field values on OIDCConfig with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *OIDCConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on OIDCConfig with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in OIDCConfigMultiError, or
// nil if none found.
func (m *OIDCConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *OIDCConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for ConfigurationUri

	// no validation rules for AuthorizationUri

	// no validation rules for TokenUri

	if utf8.RuneCountInString(m.GetCallbackUri()) < 1 {
		err := OIDCConfigValidationError{
			field:  "CallbackUri",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if utf8.RuneCountInString(m.GetClientId()) < 1 {
		err := OIDCConfigValidationError{
			field:  "ClientId",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetClientSecretRefreshInterval()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "ClientSecretRefreshInterval",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "ClientSecretRefreshInterval",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetClientSecretRefreshInterval()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "ClientSecretRefreshInterval",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for CookieNamePrefix

	if m.GetIdToken() == nil {
		err := OIDCConfigValidationError{
			field:  "IdToken",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if all {
		switch v := interface{}(m.GetIdToken()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "IdToken",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "IdToken",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetIdToken()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "IdToken",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetAccessToken()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "AccessToken",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "AccessToken",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetAccessToken()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "AccessToken",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetLogout()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "Logout",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "Logout",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetLogout()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "Logout",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for AbsoluteSessionTimeout

	// no validation rules for IdleSessionTimeout

	if all {
		switch v := interface{}(m.GetTrustedCertificateAuthorityRefreshInterval()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "TrustedCertificateAuthorityRefreshInterval",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "TrustedCertificateAuthorityRefreshInterval",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetTrustedCertificateAuthorityRefreshInterval()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "TrustedCertificateAuthorityRefreshInterval",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	// no validation rules for ProxyUri

	if all {
		switch v := interface{}(m.GetRedisSessionStoreConfig()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "RedisSessionStoreConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "RedisSessionStoreConfig",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetRedisSessionStoreConfig()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "RedisSessionStoreConfig",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if all {
		switch v := interface{}(m.GetSkipVerifyPeerCert()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "SkipVerifyPeerCert",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfigValidationError{
					field:  "SkipVerifyPeerCert",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetSkipVerifyPeerCert()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfigValidationError{
				field:  "SkipVerifyPeerCert",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	switch v := m.JwksConfig.(type) {
	case *OIDCConfig_Jwks:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "JwksConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		// no validation rules for Jwks
	case *OIDCConfig_JwksFetcher:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "JwksConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetJwksFetcher()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "JwksFetcher",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "JwksFetcher",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetJwksFetcher()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return OIDCConfigValidationError{
					field:  "JwksFetcher",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}
	oneofClientSecretConfigPresent := false
	switch v := m.ClientSecretConfig.(type) {
	case *OIDCConfig_ClientSecret:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "ClientSecretConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofClientSecretConfigPresent = true
		// no validation rules for ClientSecret
	case *OIDCConfig_ClientSecretRef:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "ClientSecretConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofClientSecretConfigPresent = true

		if all {
			switch v := interface{}(m.GetClientSecretRef()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "ClientSecretRef",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "ClientSecretRef",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetClientSecretRef()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return OIDCConfigValidationError{
					field:  "ClientSecretRef",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	case *OIDCConfig_ClientSecretFile:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "ClientSecretConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		oneofClientSecretConfigPresent = true
		// no validation rules for ClientSecretFile
	default:
		_ = v // ensures v is used
	}
	if !oneofClientSecretConfigPresent {
		err := OIDCConfigValidationError{
			field:  "ClientSecretConfig",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}
	switch v := m.TrustedCaConfig.(type) {
	case *OIDCConfig_TrustedCertificateAuthority:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "TrustedCaConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		// no validation rules for TrustedCertificateAuthority
	case *OIDCConfig_TrustedCertificateAuthorityFile:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "TrustedCaConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}
		// no validation rules for TrustedCertificateAuthorityFile
	case *OIDCConfig_TrustedCertificateAuthoritySecret:
		if v == nil {
			err := OIDCConfigValidationError{
				field:  "TrustedCaConfig",
				reason: "oneof value cannot be a typed-nil",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

		if all {
			switch v := interface{}(m.GetTrustedCertificateAuthoritySecret()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "TrustedCertificateAuthoritySecret",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, OIDCConfigValidationError{
						field:  "TrustedCertificateAuthoritySecret",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetTrustedCertificateAuthoritySecret()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return OIDCConfigValidationError{
					field:  "TrustedCertificateAuthoritySecret",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		_ = v // ensures v is used
	}

	if len(errors) > 0 {
		return OIDCConfigMultiError(errors)
	}

	return nil
}

// OIDCConfigMultiError is an error wrapping multiple validation errors
// returned by OIDCConfig.ValidateAll() if the designated constraints aren't met.
type OIDCConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m OIDCConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m OIDCConfigMultiError) AllErrors() []error { return m }

// OIDCConfigValidationError is the validation error returned by
// OIDCConfig.Validate if the designated constraints aren't met.
type OIDCConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e OIDCConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e OIDCConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e OIDCConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e OIDCConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e OIDCConfigValidationError) ErrorName() string { return "OIDCConfigValidationError" }

// Error satisfies the builtin error interface
func (e OIDCConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sOIDCConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = OIDCConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = OIDCConfigValidationError{}

// Validate checks the field values on OIDCConfig_JwksFetcherConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *OIDCConfig_JwksFetcherConfig) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on OIDCConfig_JwksFetcherConfig with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// OIDCConfig_JwksFetcherConfigMultiError, or nil if none found.
func (m *OIDCConfig_JwksFetcherConfig) ValidateAll() error {
	return m.validate(true)
}

func (m *OIDCConfig_JwksFetcherConfig) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for JwksUri

	// no validation rules for PeriodicFetchIntervalSec

	if all {
		switch v := interface{}(m.GetSkipVerifyPeerCert()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, OIDCConfig_JwksFetcherConfigValidationError{
					field:  "SkipVerifyPeerCert",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, OIDCConfig_JwksFetcherConfigValidationError{
					field:  "SkipVerifyPeerCert",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetSkipVerifyPeerCert()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return OIDCConfig_JwksFetcherConfigValidationError{
				field:  "SkipVerifyPeerCert",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return OIDCConfig_JwksFetcherConfigMultiError(errors)
	}

	return nil
}

// OIDCConfig_JwksFetcherConfigMultiError is an error wrapping multiple
// validation errors returned by OIDCConfig_JwksFetcherConfig.ValidateAll() if
// the designated constraints aren't met.
type OIDCConfig_JwksFetcherConfigMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m OIDCConfig_JwksFetcherConfigMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m OIDCConfig_JwksFetcherConfigMultiError) AllErrors() []error { return m }

// OIDCConfig_JwksFetcherConfigValidationError is the validation error returned
// by OIDCConfig_JwksFetcherConfig.Validate if the designated constraints
// aren't met.
type OIDCConfig_JwksFetcherConfigValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e OIDCConfig_JwksFetcherConfigValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e OIDCConfig_JwksFetcherConfigValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e OIDCConfig_JwksFetcherConfigValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e OIDCConfig_JwksFetcherConfigValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e OIDCConfig_JwksFetcherConfigValidationError) ErrorName() string {
	return "OIDCConfig_JwksFetcherConfigValidationError"
}

// Error satisfies the builtin error interface
func (e OIDCConfig_JwksFetcherConfigValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sOIDCConfig_JwksFetcherConfig.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = OIDCConfig_JwksFetcherConfigValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = OIDCConfig_JwksFetcherConfigValidationError{}

// Validate checks the field values on OIDCConfig_SecretReference with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *OIDCConfig_SecretReference) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on OIDCConfig_SecretReference with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// OIDCConfig_SecretReferenceMultiError, or nil if none found.
func (m *OIDCConfig_SecretReference) ValidateAll() error {
	return m.validate(true)
}

func (m *OIDCConfig_SecretReference) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for Namespace

	if utf8.RuneCountInString(m.GetName()) < 1 {
		err := OIDCConfig_SecretReferenceValidationError{
			field:  "Name",
			reason: "value length must be at least 1 runes",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		return OIDCConfig_SecretReferenceMultiError(errors)
	}

	return nil
}

// OIDCConfig_SecretReferenceMultiError is an error wrapping multiple
// validation errors returned by OIDCConfig_SecretReference.ValidateAll() if
// the designated constraints aren't met.
type OIDCConfig_SecretReferenceMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m OIDCConfig_SecretReferenceMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m OIDCConfig_SecretReferenceMultiError) AllErrors() []error { return m }

// OIDCConfig_SecretReferenceValidationError is the validation error returned
// by OIDCConfig_SecretReference.Validate if the designated constraints aren't met.
type OIDCConfig_SecretReferenceValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e OIDCConfig_SecretReferenceValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e OIDCConfig_SecretReferenceValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e OIDCConfig_SecretReferenceValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e OIDCConfig_SecretReferenceValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e OIDCConfig_SecretReferenceValidationError) ErrorName() string {
	return "OIDCConfig_SecretReferenceValidationError"
}

// Error satisfies the builtin error interface
func (e OIDCConfig_SecretReferenceValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sOIDCConfig_SecretReference.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = OIDCConfig_SecretReferenceValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = OIDCConfig_SecretReferenceValidationError{}
