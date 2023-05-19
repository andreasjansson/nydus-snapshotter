package auth

import (
	"github.com/containerd/containerd/log"
	"github.com/containerd/nydus-snapshotter/pkg/gcp"
)

func FromGCPToken(host string) *PassKeyChain {
	if !gcp.IsEnabled() {
		return nil
	}

	if !gcp.HostIsGCP(host) {
		return nil
	}

	password := gcp.GetPassword()
	if password == "" {
		log.L.Warn("GCP auth is enabled but password is empty")
		return nil
	}

	return &PassKeyChain{
		Username: "_token",
		Password: password,
	}
}
