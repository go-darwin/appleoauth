// Copyright 2021 The Go Darwin Authors
// SPDX-License-Identifier: BSD-3-Clause

package appleoauth

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

func ask(r io.Reader, question string, answer ...string) (string, bool) {
	reader := bufio.NewReader(r)

	var answers map[string]bool
	if len(answer) > 0 {
		answers := make(map[string]bool, len(answer))
		for _, ans := range answer {
			answers[ans] = true
		}
	}

	for {
		fmt.Printf("%s", question)

		resp, err := reader.ReadString('\n')
		if err != nil {
			return "", false
		}
		resp = strings.ToLower(strings.TrimSpace(resp))

		if len(answers) > 0 {
			if ans, ok := answers[resp]; ok {
				return resp, ans
			}
			// donsn't matched answers, continue
			continue
		}

		return resp, true
	}
}
