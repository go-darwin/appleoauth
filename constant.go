// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

const (
	ProtocolVersion  = "QH5B2"
	defaultUserAgent = "go-darwin/appleoauth"
)

const (
	// EnvIcloudUserName is the environment variable for login username to Apple web service.
	EnvIcloudUserName = "APPLE_USERNAME"

	// EnvIcloudPassword is the environment variable for login password to Apple web service.
	EnvIcloudPassword = "APPLE_PASSWORD"

	Env2FASMSDefaultPhoneNumber = "APPLEOAUTH_2FA_SMS_DEFAULT_PHONE_NUMBER"
)

const (
	HdrContentType       = "Content-Type"
	HdrXRequestedWith    = "X-Requested-With"
	HdrXAppleWidgetKey   = "X-Apple-Widget-Key"
	HdrAccept            = "Accept"
	HdrXAppleIDSessionID = "X-Apple-ID-Session-Id"
	HdrScnt              = "scnt"
)
