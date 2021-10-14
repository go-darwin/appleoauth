// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
)

func (c *Client) handleTwoStep(ctx context.Context, resp *authOptionsResponse) error {
	if scode := resp.SecurityCode; scode != nil && scode.TooManyCodesLock {
		return ErrTooManyVerificationCodes
	}

	answers := make([]string, len(resp.TrustedDevices))
	for i, device := range resp.TrustedDevices {
		answers[i] = fmt.Sprint(i + 1)
		fmt.Printf("%d): %s\t%s: SMS: %d\n", i, device.Name, device.ModelName, device.ID)
	}

	ans, ok := ask(os.Stdin, "Please select a trusted device to verify your identity", answers...)
	if !ok {
		return errors.New("could not read from stdin")
	}

	a, err := strconv.Atoi(ans)
	if err != nil {
		return err
	}

	return c.handleTwoStepForDevice(ctx, resp.TrustedDevices[a].ID)
}

func (c *Client) handleTwoStepForDevice(ctx context.Context, deviceID int) error {
	// request token to device
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, fmt.Sprintf(endpoints[submitSecurityCode], deviceID), nil)
	if err != nil {
		return err
	}

	// set required headers
	req.Header = c.updateRequestHeaders(req.Header.Clone())

	// TODO(zchee): implements HandleITuneConnectResponse
	return ErrNotImplemented
}
