// The Go adapter of interop-clients: golang.org/x/oauth2 and go-oidc from the module proxy, pinned here
// and by go.sum's hashes.
module interop/go-adapter

// x/oauth2 v0.37.0 asks Go 1.26 at least; the toolchain builds with is pinned below.
go 1.26.0

toolchain go1.26.4

require (
	github.com/coreos/go-oidc/v3 v3.21.0
	golang.org/x/oauth2 v0.37.0
)

require github.com/go-jose/go-jose/v4 v4.1.4 // indirect
