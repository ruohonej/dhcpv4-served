module dhcpv4-served

go 1.26.0

require (
	github.com/insomniacslk/dhcp v0.0.0-20261014062924-c6bb46ad3f3a
	github.com/landlock-lsm/go-landlock v0.11.2
	github.com/mdlayher/netlink v1.11.2
	github.com/varlink/go/v2 v2.0.0-20260611234345-b30f18e21e83
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/mdlayher/socket v0.6.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.14 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	golang.org/x/sync v0.20.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.78 // indirect
)

replace github.com/varlink/go/v2 => github.com/noxiouz/go/v2 v2.0.0-20260611234345-b30f18e21e83
