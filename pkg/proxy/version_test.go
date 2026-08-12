package proxy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"goproxy"
)

// The VERSION file is what the release workflow tags from, so the binary has to
// report exactly what is in it - trimmed, and nothing else.
func TestVersionComesFromTheVersionFile(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "VERSION"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.TrimSpace(string(raw))
	if want == "" {
		t.Fatal("the VERSION file is empty")
	}
	if goproxy.Version != want {
		t.Errorf("embedded version = %q, VERSION file = %q", goproxy.Version, want)
	}
	if got := Version().Version; got != want {
		t.Errorf("Version().Version = %q, want %q", got, want)
	}
	if strings.ContainsAny(goproxy.Version, " \t\r\n") {
		t.Errorf("the embedded version has whitespace in it: %q", goproxy.Version)
	}
}

// The workflow refuses to release a VERSION that is not a version, so the file
// in the repository has to be one.
func TestVersionFileIsAVersion(t *testing.T) {
	semver := regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	if !semver.MatchString(goproxy.Version) {
		t.Errorf("VERSION is %q, want something like 1.2.3 or 1.2.3-rc1", goproxy.Version)
	}
}

func TestVersionString(t *testing.T) {
	got := Version().String()
	if !strings.HasPrefix(got, "goproxy version "+goproxy.Version) {
		t.Errorf("Version().String() = %q, want it to start with the version", got)
	}
	if !strings.Contains(got, "go1.") {
		t.Errorf("Version().String() = %q, want the Go version in it", got)
	}
}
