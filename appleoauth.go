// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"

	"github.com/go-logr/logr"
	"golang.org/x/net/publicsuffix"
)

var (
	ErrInvalidUsernameOrPassword = errors.New("invalid username and password combination")
	ErrRequiredPrivacyAck        = errors.New("needs to manually sign in to https://appleid.apple.com (or https://appstoreconnect.apple.com) and acknowledge the Apple ID and Privacy agreement")
	ErrUpgradeTwoFactorAuth      = errors.New("this account is being prompted to upgrade to Two-factor authentication")
	ErrInvalidPhoneNumber        = errors.New("not a valid phone number")
	ErrNoTrustedPhoneNumbers     = errors.New("account doesn't have any trusted phone numbers, but they're required for two-factor authentication. see https://support.apple.com/en-ca/HT204915")
	ErrNotAuthenticated          = errors.New("already signed out")
	ErrUnexpectedSigninResponse  = errors.New("unexpected sign in response")
	ErrTooManyVerificationCodes  = errors.New("too many verification codes have been sent")
	ErrEmpty2FAEnv               = fmt.Errorf("%s environment variable is empty", Env2FASMSDefaultPhoneNumber)

	ErrNotImplemented = errors.New("not implemented")
)

type endpoint uint8

const (
	iTunesConnect endpoint = 1 + iota
	signin
	authOptions
	requestSecurityCode
	submitSecurityCode
	trust
	olympusSession
)

var endpoints = map[endpoint]string{
	iTunesConnect:       "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com",
	signin:              "https://idmsa.apple.com/appleauth/auth/signin",
	authOptions:         "https://idmsa.apple.com/appleauth/auth",
	requestSecurityCode: "https://idmsa.apple.com/appleauth/auth/verify/phone",
	submitSecurityCode:  "https://idmsa.apple.com/appleauth/auth/verify/%s/securitycode", // codeType, deviceID
	trust:               "https://idmsa.apple.com/appleauth/auth/2sv/trust",
	olympusSession:      "https://appstoreconnect.apple.com/olympus/v1/session",
}

var authTypes = map[string]bool{
	"sa":     true,
	"hsa":    true,
	"non-sa": true,
	"hsa2":   true,
}

var (
	logger   = logr.Discard()
	loggerMu sync.Mutex
)

// SetLogger sets logr.Logger to logger.
func SetLogger(l logr.Logger) {
	loggerMu.Lock()
	logger = l
	loggerMu.Unlock()
}

var (
	// cookiejar.New always returns nil error
	jar, _        = cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	DefaultClient = &http.Client{
		Jar: jar,
	}
)

// Client represents a Apple OAuth2 client.
type Client struct {
	hc         *http.Client
	serviceKey string
	username   string
	sessionID  string
	scnt       string

	userEmail string
	provider  *olympusProvider
}

// NewClient returns the new Client.
func NewClient(hc *http.Client) *Client {
	if hc == nil {
		hc = DefaultClient
	}

	return &Client{
		hc: hc,
	}
}

type iTuneConnectResponse struct {
	AuthServiceURL string `json:"authServiceUrl"`
	AuthServiceKey string `json:"authServiceKey"`
}

// FetchServiceKey fetch serviceKey to authenticate to Apple's web service from the iTunes Connect endpoint.
func (c *Client) FetchServiceKey(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints[iTunesConnect], nil)
	if err != nil {
		return err
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var itcResp iTuneConnectResponse
	if err := json.NewDecoder(resp.Body).Decode(&itcResp); err != nil {
		return fmt.Errorf("could not unmarshal response body: %w", err)
	}

	const wantAuthServiceURL = "https://idmsa.apple.com/appleauth"
	if !strings.EqualFold(itcResp.AuthServiceURL, wantAuthServiceURL) {
		return fmt.Errorf("could not find %q response. Apple has been changed authenticate method", wantAuthServiceURL)
	}
	if itcResp.AuthServiceKey == "" {
		return fmt.Errorf("could not find %q response", "authServiceKey")
	}

	logger.V(1).Info("got serviceKey from response", "authServiceUrl", itcResp.AuthServiceURL, "authServiceKey", itcResp.AuthServiceKey)
	c.serviceKey = itcResp.AuthServiceKey

	return nil
}

// Account represents a Apple Developer account.
type Account struct {
	Username string
	Password string
}

// Valid reports whether the Account is valid.
func (a Account) Valid() bool {
	if a.Username == "" || a.Password == "" {
		return false
	}

	return true
}

type signinRequest struct {
	AccountName string `json:"accountName"`
	Password    string `json:"password"`
	RememberMe  bool   `json:"rememberMe"`
}

type signinResponse struct {
	AuthType      string         `json:"authType"`
	ServiceErrors []ServiceError `json:"serviceErrors,omitempty"`
}

// ServiceError represents a Apple service error.
type ServiceError struct {
	Code    string `json:"code,omitempty"`
	Title   string `json:"title,omitempty"`
	Message string `json:"message,omitempty"`
}

// Error returns the string representation of a ServiceError.
func (e ServiceError) Error() string {
	return fmt.Sprintf("(%s): (%s)", e.Code, e.Message)
}

// Login logins to Apple's web service.
func (c *Client) Login(ctx context.Context, account *Account) error {
	if !account.Valid() {
		user, ok := os.LookupEnv(EnvIcloudUserName)
		if !ok {
			return ErrInvalidUsernameOrPassword
		}
		account.Username = user

		password, ok := os.LookupEnv(EnvIcloudPassword)
		if !ok {
			return ErrInvalidUsernameOrPassword
		}
		account.Password = password
	}
	c.username = account.Username

	// create request body
	reqBody := signinRequest{
		AccountName: account.Username,
		Password:    account.Password,
		RememberMe:  true,
	}
	body, err := json.Marshal(&reqBody)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoints[signin], bytes.NewReader(body))
	if err != nil {
		return err
	}

	// set require headers
	req.Header.Set(HdrContentType, "application/json")
	req.Header.Set(HdrXRequestedWith, "XMLHttpRequest")
	req.Header.Set(HdrXAppleWidgetKey, c.serviceKey)
	req.Header.Set(HdrAccept, "application/json")
	req.Header.Add(HdrAccept, "text/javascript")

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// unmarshal before checks status code for 412 code
	var signinResp signinResponse
	if err := json.NewDecoder(resp.Body).Decode(&signinResp); err != nil {
		return fmt.Errorf("could not unmarshal response body: %w", err)
	}

	switch code := resp.StatusCode; code {
	case http.StatusOK: // 200
		// nothig to do

	case http.StatusForbidden: // 403
		return ErrInvalidUsernameOrPassword

	case http.StatusUnauthorized: // 401
		return fmt.Errorf("status code is %s", http.StatusText(code))

	case http.StatusConflict: // 409
		if err := c.handleTwoStepOrFactor(ctx, resp); err != nil {
			return err
		}

	case http.StatusPreconditionFailed: // 412
		if !authTypes[signinResp.AuthType] {
			return errors.New("this account is being prompted to upgrade to Two-factor authentication")
		}
		return ErrRequiredPrivacyAck

	case http.StatusBadGateway: // 502
		return errors.New("temporary Apple server error, try again later")

	default:
		return ErrUnexpectedSigninResponse
	}

	logger.Info("successful login")

	return nil
}

type olympusProvider struct {
	ProviderID   string `json:"providerId,omitempty"`
	Name         string `json:"name,omitempty"`
	ContentTypes string `json:"contentTypes,omitempty"`
}

type olympusSessionResponse struct {
	User *struct {
		EmailAddress string `json:"emailAddress,omitempty"`
	} `json:"user,omitempty"`

	Provider *olympusProvider `json:"provider,omitempty"`
}

// FetchOlympusSession fetch the "itctx" from the new "olympus" (22nd May 2017) API endpoint.
func (c *Client) FetchOlympusSession(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoints[olympusSession], nil)
	if err != nil {
		return err
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var olympusResp olympusSessionResponse
	if err := json.NewDecoder(resp.Body).Decode(&olympusResp); err != nil {
		return fmt.Errorf("could not decode request body: %w", err)
	}

	if user := olympusResp.User; user != nil {
		c.userEmail = user.EmailAddress
	}

	if olympusProvider := olympusResp.Provider; olympusProvider != nil {
		c.provider = olympusProvider
	}

	return c.storeSession(ctx)
}
