// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

//go:build !linux

package tracefs

import (
	"errors"
	"os"
)

var errNotLinux = errors.New("tracefs: not supported on this platform")

// Root returns the tracing root path.
func Root() (string, error) {
	return "", errNotLinux
}

// ReadFile reads the relative path provided, using the detected root of tracefs or debugfs.
func ReadFile(relname string) ([]byte, error) {
	return nil, errNotLinux
}

// Open opens the relative path provided (similar to os.Open), using the detected root of tracefs or debugfs.
func Open(relname string) (*os.File, error) {
	return nil, errNotLinux
}

// OpenFile opens the relative path provided (similar to os.OpenFile), using the detected root of tracefs or debugfs.
func OpenFile(relname string, flag int, perm os.FileMode) (*os.File, error) {
	return nil, errNotLinux
}
