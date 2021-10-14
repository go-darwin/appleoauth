// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

import (
	"testing"
)

func Test_matchPhoneNumberToMasked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		phoneNumber string
		masked      string
		wantMatched bool
	}{
		{
			name:        "+49 162 1234567",
			phoneNumber: "+49 162 1234567",
			masked:      "+49 •••• •••••67",
			wantMatched: true,
		},
		{
			name:        "+1-123-456-7866",
			phoneNumber: "+1-123-456-7866",
			masked:      "+1 (•••) •••-••66",
			wantMatched: true,
		},
		{
			name:        "+49 123 4567885",
			phoneNumber: "+49 123 4567885",
			masked:      "+49 •••• •••••85",
			wantMatched: true,
		},
		{
			name:        "+4912341234581",
			phoneNumber: "+4912341234581",
			masked:      "+49 ••••• •••••81",
			wantMatched: true,
		},
		{
			name:        "+1-123-456-7866",
			phoneNumber: "+1-123-456-7866",
			masked:      "+1 (•••) •••-••66",
			wantMatched: true,
		},
		{
			name:        "+39 123 456 7871",
			phoneNumber: "+39 123 456 7871",
			masked:      "+39 ••• ••• ••71",
			wantMatched: true,
		},
		{
			name:        "+353123456743",
			phoneNumber: "+353123456743",
			masked:      "+353 •• ••• ••43",
			wantMatched: true,
		},
		{
			name:        "+375 00 000-00-59",
			phoneNumber: "+375 00 000-00-59",
			masked:      "+375 • ••• •••-••-59",
			wantMatched: true,
		},
		{
			name:        "not match/+49 162 1234567",
			phoneNumber: "+49 162 1234567",
			masked:      "+49 •••• •••••76",
			wantMatched: false,
		},
		{
			name:        "not match/+1-123-456-7866",
			phoneNumber: "+1-123-456-7866",
			masked:      "+49 •••• •••••67",
			wantMatched: false,
		},
	}
	for _, tt := range tests {
		// tt := tt
		t.Run(tt.name, func(t *testing.T) {
			// t.Parallel()

			if gotMatched := matchPhoneNumberToMasked(tt.phoneNumber, tt.masked); gotMatched != tt.wantMatched {
				t.Fatalf("matchPhoneNumberToMasked(%q, %q) = %v, want %v", tt.phoneNumber, tt.masked, gotMatched, tt.wantMatched)
			}
		})
	}
}
