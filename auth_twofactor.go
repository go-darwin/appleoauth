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
	"regexp"
	"strings"
	"unicode"
)

type securityCode struct {
	Code string `json:"code"`
}

type phoneNumberID struct {
	ID int `json:"id"`
}

type twoFactorCodeFromPhoneRequest struct {
	SecurityCode *securityCode  `json:"securityCode,omitempty"`
	PhoneNumber  *phoneNumberID `json:"phoneNumber,omitempty"`
	Mode         string         `json:"mode,omitempty"`
}

type submitSecurityCodeResponse struct {
	ServiceErrors []ServiceError `json:"service_errors,omitempty"`
	HasError      bool           `json:"hasError,omitempty"`
}

// handleTwoFactor handles Two-factor authentication.
func (c *Client) handleTwoFactor(ctx context.Context, authResp *authOptionsResponse) (err error) {
	logger.V(1).Info(fmt.Sprintf("Two-factor Authentication (6 digits code) is enabled for %q account", c.username))
	logger.V(1).Info("More information about Apple Two-factor Authentication: https://support.apple.com/en-us/HT204915")

	// verification code has already be pushed to devices
	secCode := authResp.SecurityCode
	if secCode == nil {
		return errors.New("invalid auth option response")
	}
	codeLength := secCode.Length

	var phoneNumber string
	var body io.Reader
	var codeType string

	envPhoneNumber, ok := os.LookupEnv(Env2FASMSDefaultPhoneNumber)
	switch {
	case ok:
		phoneNumber = envPhoneNumber
		codeType = "phone"
		body, err = c.twoFactorCodeFromEnv(ctx, authResp, phoneNumber, codeLength)

	case c.isSMSAutomaticallySent(authResp):
		codeType = "phone"
		fallbackNumber := authResp.TrustedPhoneNumbers[0]
		phoneID := fallbackNumber.ID
		phoneNumber = fallbackNumber.NumberWithDialCode
		pushMode := fallbackNumber.PushMode
		body, err = c.twoFactorCodeFromPhone(ctx, phoneID, phoneNumber, pushMode, codeLength, false)

	case c.canSMSFallback(authResp):
		codeType = "phone"
		body, err = c.twoFactorCodeFromPhoneChoose(ctx, authResp.TrustedPhoneNumbers, codeLength)

	default:
		logger.Info("Input `sms` to escape this prompt and select a trusted phone number to send the code as a text message")
		logger.Info(fmt.Sprintf("You can also set the environment variable %q to automate this", Env2FASMSDefaultPhoneNumber))

		code, ok := ask(os.Stdin, fmt.Sprintf("Please enter the %d digit code: ", codeLength))
		if !ok {
			return errors.New("could not read stdin")
		}

		switch code {
		case "sms":
			codeType = "phone"
			body, err = c.twoFactorCodeFromPhoneChoose(ctx, authResp.TrustedPhoneNumbers, codeLength)

		default:
			if !validCode(code, codeLength) {
				return fmt.Errorf("not valid code: %s", code)
			}

			reqBody := twoFactorCodeFromPhoneRequest{
				SecurityCode: &securityCode{
					Code: code,
				},
			}
			data, err := json.Marshal(reqBody)
			if err != nil {
				return fmt.Errorf("marshal request body: %w", err)
			}

			codeType = "trusteddevice"
			body = bytes.NewReader(data)
		}
	}
	if err != nil {
		return err
	}

	logger.V(1).Info("requesting session...")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf(endpoints[submitSecurityCode], codeType), body)
	if err != nil {
		return err
	}
	req.Header.Set(HdrContentType, "application/json")
	req.Header = c.updateRequestHeaders(req.Header.Clone())

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}

	var submitResp submitSecurityCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&submitResp); err != nil {
		return fmt.Errorf("could not unmarshal response body: %w", err)
	}

	for _, svcErr := range submitResp.ServiceErrors {
		if strings.Contains(svcErr.Message, "Incorrect") {
			return errors.New("incorrect verification code")
		}
	}

	return nil
}

// validCode reports whether the code is valid.
func validCode(code string, codeLength int) bool {
	if len(code) != codeLength {
		return false
	}

	for _, c := range code {
		if !unicode.IsDigit(c) {
			return false
		}
	}

	return true
}

// canSMSFallback reports whether can fallback to SMS Two-factor authentication.
func (c *Client) canSMSFallback(resp *authOptionsResponse) bool {
	return resp.NoTrustedDevices
}

// isSMSAutomaticallySent reports whether the sent authentication code via SMS automatically.
func (c *Client) isSMSAutomaticallySent(resp *authOptionsResponse) bool {
	return len(resp.TrustedDevices) == 1 && c.canSMSFallback(resp)
}

// twoFactorCodeFromEnv requests Two-factor authentication token via SMS to the specific device automatically from the environment variable.
func (c *Client) twoFactorCodeFromEnv(ctx context.Context, resp *authOptionsResponse, phoneNumber string, codeLength int) (io.Reader, error) {
	logger.V(1).Info("automatically requesting 2FA token via SMS to this number from environment variable", string(Env2FASMSDefaultPhoneNumber), phoneNumber)

	var phoneID int
	var pushMode string
	for _, phone := range resp.TrustedPhoneNumbers {
		if matchPhoneNumberToMasked(phoneNumber, phone.NumberWithDialCode) {
			phoneID = phone.ID
			pushMode = phone.PushMode
			if pushMode == "" {
				// if no pushMode, assume sms mode
				pushMode = "sms"
			}
			break
		}
	}
	if phoneID == 0 || pushMode == "" {
		return nil, fmt.Errorf("doesn't matched %q phone number to your trusted devices", phoneNumber)
	}

	requestCode := !c.isSMSAutomaticallySent(resp)
	return c.twoFactorCodeFromPhone(ctx, phoneID, phoneNumber, pushMode, codeLength, requestCode)
}

// twoFactorCodeFromPhoneChoose choose the any device to the requests Two-factor authentication token via SMS.
func (c *Client) twoFactorCodeFromPhoneChoose(ctx context.Context, trustedPhoneNumbers []trustedPhoneNumber, codeLength int) (io.Reader, error) {
	return nil, ErrNotImplemented
}

// twoFactorCodeFromPhone requests Two-factor authentication token via SMS to phoneID device if neeeded, and returns the
// request body for the submit of security code to Apple.
func (c *Client) twoFactorCodeFromPhone(ctx context.Context, phoneID int, phoneNumber, pushMode string, codeLength int, requestCode bool) (io.Reader, error) {
	if requestCode {
		reqBody := twoFactorCodeFromPhoneRequest{
			PhoneNumber: &phoneNumberID{
				ID: phoneID,
			},
			Mode: pushMode,
		}
		data, err := json.Marshal(reqBody)
		if err != nil {
			return nil, err
		}

		// request code
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoints[requestSecurityCode], bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set(HdrContentType, "application/json")
		req.Header = c.updateRequestHeaders(req.Header.Clone())

		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, err
		}

		if err := c.handleItuneConnect(ctx, resp.Body); err != nil {
			return nil, err
		}
		logger.V(1).Info(fmt.Sprintf("successfully requested text message to %s", phoneNumber))
	}

	code, ok := ask(os.Stdin, fmt.Sprintf("Please enter the %d digit code you received at %q: ", codeLength, phoneNumber))
	if !ok {
		return nil, fmt.Errorf("could not read %d digit cdoe from stdin", codeLength)
	}

	if !validCode(code, codeLength) {
		return nil, fmt.Errorf("not valid code: %s", code)
	}

	reqBody := twoFactorCodeFromPhoneRequest{
		SecurityCode: &securityCode{
			Code: code,
		},
		PhoneNumber: &phoneNumberID{
			ID: phoneID,
		},
		Mode: pushMode,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(data), nil
}

// matchPhoneNumberToMasked reports whether the masked phone number matched phoneNumber.
func matchPhoneNumberToMasked(phoneNumber, masked string) (matched bool) {
	trimFunc := func(s string) string {
		for {
			idx := strings.IndexAny(s, ` -()"`)
			if idx == -1 {
				break
			}
			s = s[:idx] + s[idx+1:]
		}

		return s
	}

	// from:
	//  +49 162 1234567
	//  +1-123-456-7866
	phoneNumber = trimFunc(phoneNumber)
	// to:
	//  +491621234567
	//  +11234567866

	// from:
	//  +49 •••• •••••67
	//  +1 (•••) •••-••66
	masked = trimFunc(masked)
	// to:
	//  +49•••••••••67
	//  +1••••••••66

	// 9 or 8
	const mark = "•"
	c := strings.Count(masked, mark)

	maskedRe := regexp.MustCompile(fmt.Sprintf(`^([+0-9]{2,4})(%s{%d})([0-9]{2})$`, mark, c))
	maskedPair := maskedRe.FindStringSubmatch(masked)

	// NOTE: range from c-2 because sometimes the masked number has 1 or 2 dots(.) more than the actual number
	maskedPat := fmt.Sprintf(`^\%s([0-9]{%d,%d})%s$`, maskedPair[1], c-2, c, maskedPair[3])
	// regexp:
	//  ^\+49([0-9]{8,9})67$
	//  ^\+1([0-9]{7,8})66$

	// matches
	//  ^\+49([0-9]{8})67$
	// to
	//  +491621234567
	matched = regexp.MustCompile(maskedPat).MatchString(phoneNumber)

	return matched
}
