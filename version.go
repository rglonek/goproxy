// Package goproxy is the module root. It exists to carry the version, which is
// embedded from the VERSION file at the top of the repository so that one file
// is the single source of truth: the release workflow tags from it, and the
// binary reports the same string without anyone having to remember a build
// flag.
package goproxy

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version is the version of goproxy, from the VERSION file. Bump that file to
// release; nothing else needs to change.
var Version = strings.TrimSpace(versionFile)
