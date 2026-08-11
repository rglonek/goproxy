package proxy

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Build information. version is baked in at build time with
//
//	-ldflags "-X goproxy/pkg/proxy.version=1.2.3"
//
// commit and date are read from the embedded VCS stamp when they are not set
// explicitly, so a `go build` of a clean checkout still reports them.
var (
	version   = "0.3.0"
	commit    = ""
	buildDate = ""
)

// BuildInfo describes the running binary.
type BuildInfo struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
}

// Version returns the version of the goproxy binary.
func Version() BuildInfo {
	info := BuildInfo{
		Version:   version,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
	}
	if info.Commit != "" && info.BuildDate != "" {
		return info
	}
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	var revision, revisionTime string
	var modified bool
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.time":
			revisionTime = setting.Value
		case "vcs.modified":
			modified = setting.Value == "true"
		}
	}
	if info.Commit == "" && revision != "" {
		info.Commit = revision
		if modified {
			info.Commit += "-dirty"
		}
	}
	if info.BuildDate == "" {
		info.BuildDate = revisionTime
	}
	return info
}

func (b BuildInfo) String() string {
	parts := []string{"goproxy version " + b.Version}
	if b.Commit != "" {
		parts = append(parts, "commit "+b.Commit)
	}
	if b.BuildDate != "" {
		parts = append(parts, "built "+b.BuildDate)
	}
	parts = append(parts, b.GoVersion)
	return strings.Join(parts, ", ")
}
