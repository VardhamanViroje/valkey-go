module test

go 1.26.6

require (
	github.com/valkey-io/valkey-go v1.0.78
	github.com/valkey-io/valkey-go/valkeycompat v1.0.78
)

require golang.org/x/sys v0.47.0 // indirect

replace github.com/valkey-io/valkey-go => /usr/local/google/home/viroje/project/valkey/valkey-go

replace github.com/valkey-io/valkey-go/valkeycompat => /usr/local/google/home/viroje/project/valkey/valkey-go/valkeycompat
