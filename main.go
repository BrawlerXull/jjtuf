// Copyright The jjtuf Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/jjtuf/jjtuf/internal/cmd/root"
)

func main() {
	if err := root.New().Execute(); err != nil {
		os.Exit(1)
	}
}
