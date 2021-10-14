// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	yaml "github.com/goccy/go-yaml"
)

type trustedPhoneNumber struct {
	ID                 int    `json:"id"`
	NumberWithDialCode string `json:"numberWithDialCode"`
	PushMode           string `json:"pushMode"`
}

type trustedDevice struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	ModelName string `json:"modelName"`
}

type securityCodeResponse struct {
	Length                int  `json:"length"`
	TooManyCodesSent      bool `json:"tooManyCodesSent,omitempty"`
	TooManyCodesLock      bool `json:"tooManyCodesLock,omitempty"`
	TooManyCodesValidated bool `json:"tooManyCodesValidated,omitempty"`
	SecurityCodeLocked    bool `json:"securityCodeLocked,omitempty"`
	SecurityCodeCooldown  bool `json:"securityCodeCooldown,omitempty"`
}

type authOptionsResponse struct {
	TrustedPhoneNumbers []trustedPhoneNumber  `json:"trustedPhoneNumbers,omitempty"`
	TrustedDevices      []trustedDevice       `json:"trustedDevices,omitempty"`
	ServiceErrors       []ServiceError        `json:"serviceErrors,omitempty"`
	SecurityCode        *securityCodeResponse `json:"securityCode,omitempty"`
	NoTrustedDevices    bool                  `json:"noTrustedDevices"`
}

// canFallBackToSMS reports whether the can fallBack to sms Two-factor authentication.
//
// One time with a new testing account I had a response where noTrustedDevices was nil, but the account didn't have any trusted devices.
// This should have been a situation where an SMS security code was sent automatically.
// This resolved itself either after some time passed, or by signing into appleid.apple.com with the account.
//
// Not sure if it's worth explicitly handling this case or if it'll be really rare.
func (r *authOptionsResponse) canFallBackToSMS() bool {
	return r.NoTrustedDevices
}

// isSMSAutomaticallySent reports whether the automatically sent SMS from trusted device.
func (r *authOptionsResponse) isSMSAutomaticallySent() bool {
	return r.TrustedPhoneNumbers != nil && len(r.TrustedPhoneNumbers) == 1 && r.canFallBackToSMS()
}

type twoFactorKind uint8

const (
	kindUnknown twoFactorKind = iota
	kindTwoStep twoFactorKind = 1 << iota
	kindTwoFactor
)

// kind returns the kind of Two Factor.
func (r *authOptionsResponse) kind() twoFactorKind {
	switch {
	case r.TrustedDevices != nil:
		return kindTwoStep
	case r.TrustedPhoneNumbers != nil:
		return kindTwoFactor
	default:
		return kindUnknown
	}
}

// handleTwoStepOrFactor handles Two Factor authentication or Two step authentication.
func (c *Client) handleTwoStepOrFactor(ctx context.Context, signinResp *http.Response) error {
	// extract `X-Apple-Id-Session-Id` and `scnt` from response
	c.sessionID = signinResp.Header.Get(HdrXAppleIDSessionID)
	c.scnt = signinResp.Header.Get(HdrScnt)

	// get authentication options
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints[authOptions], nil)
	if err != nil {
		return err
	}
	// set required headers
	req.Header = c.updateRequestHeaders(req.Header.Clone())

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var authOptionsResp authOptionsResponse
	if err := json.NewDecoder(resp.Body).Decode(&authOptionsResp); err != nil {
		return fmt.Errorf("could not unmarshal response body: %w", err)
	}

	switch authOptionsResp.kind() {
	case kindTwoStep:
		return c.handleTwoStep(ctx, &authOptionsResp)

	case kindTwoFactor:
		return c.handleTwoFactor(ctx, &authOptionsResp)

	case kindUnknown:
		return errors.New("an Apple indicated activated Two-step verification or Two-factor Authentication but didn't know how to handle this response")
	}

	return errors.New("unreachable")
}

// handleItuneConnect handles iTune Connect response.
func (c *Client) handleItuneConnect(ctx context.Context, body io.ReadCloser /*, flakyAPICall bool*/) error {
	if body == nil {
		return errors.New("body is nil")
	}

	return nil
}

// storeSession stores session to local file.
func (c *Client) storeSession(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints[trust], nil)
	if err != nil {
		return err
	}
	req.Header = c.updateRequestHeaders(req.Header.Clone())

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()

	// save cookies
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	for _, cookie := range resp.Cookies() {
		logger.V(1).Info("storeSession", "cookie", cookie)
		if err := enc.Encode(&cookie); err != nil {
			return fmt.Errorf("could not encode cookie: %w", err)
		}
	}

	if err := os.WriteFile("cookies.yaml", buf.Bytes(), 0644); err != nil {
		return err
	}

	return nil
}

// updateRequestHeaders updates required request headers.
func (c *Client) updateRequestHeaders(header http.Header) http.Header {
	header.Set(HdrXAppleIDSessionID, c.sessionID)
	header.Set(HdrXAppleWidgetKey, c.serviceKey)
	header.Set(HdrAccept, "application/json")
	header.Set(HdrScnt, c.scnt)

	return header
}
