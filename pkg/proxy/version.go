package proxy

import (
	"runtime"
	"runtime/debug"
	"strings"

	"goproxy"
)

// The version comes from the VERSION file at the top of the repository, which
// is embedded at compile time - there is no build flag to forget. commit and
// date are read from the embedded VCS stamp, or can be set explicitly with
//
//	-ldflags "-X goproxy/pkg/proxy.commit=abc1234"
var (
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
		Version:   goproxy.Version,
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
