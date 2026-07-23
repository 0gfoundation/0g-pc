package core

import (
	"context"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Resolver decides, for a given request, which provider enclave the client
// should seal to. It exists so the same client core serves both selection
// shapes without branching in the seal path:
//
//   - the route resolver (client/route), used by both shipped server forms —
//     the sidecar and the gateway — asks the 0G router per request which
//     provider to use and fetches that provider's enc key from the broker;
//   - a static resolver returns one fixed provider, for a caller that already
//     holds a provider identity (tests, or a future verified-quote/direct-seal
//     path).
//
// Resolve runs on the request path, before sealing, so an implementation that
// makes network calls (route mode) should honor ctx for cancellation/deadline.
// A failure should be returned as a staged *Error so the proxy maps it to a
// sensible HTTP status; a plain error is treated as an upstream (502) failure.
type Resolver interface {
	Resolve(ctx context.Context, req wire.Request) (Provider, error)
}

// staticResolver always returns the same provider, ignoring the request — the
// low-level case for a caller that already holds a provider identity. It backs
// core.New and is used mainly by tests and any direct-seal-to-a-known-provider
// caller; the shipped server forms route instead (client/route).
type staticResolver struct{ provider Provider }

func (s staticResolver) Resolve(context.Context, wire.Request) (Provider, error) {
	return s.provider, nil
}
