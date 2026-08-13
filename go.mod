module goproxy

go 1.25.0

// Pin the toolchain to a patched release: every stdlib finding govulncheck
// reports is "fixed in go1.25.x", so the floor belongs in the repo rather than
// in whichever Go the machine happens to have.
toolchain go1.25.12

require (
	github.com/rglonek/logger v0.2.2
	golang.org/x/crypto v0.55.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/text v0.41.0 // indirect
)
