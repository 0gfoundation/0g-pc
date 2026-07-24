package core

import (
	"context"

	"github.com/0gfoundation/0g-pc-e2ee/protocol/wire"
)

// Resolver decides, for a given request, which provider enclaves the client
// should seal to. It exists so the same client core serves both selection
// shapes without branching in the seal path:
//
//   - the route resolver (client/route), used by both shipped server forms —
//     the sidecar and the gateway — asks the 0G router per request which
//     providers to use and fetches the chosen provider's enc key from the broker;
//   - a static resolver returns one fixed provider, for a caller that already
//     holds a provider identity (tests, or a future verified-quote/direct-seal
//     path).
//
// Resolve returns an ordered list of Candidates — best first — so the client can
// fall back to the next provider when one fails (SPEC §4.4). It runs on the
// request path, before sealing, so an implementation that makes network calls
// (route mode) should honor ctx for cancellation/deadline. A failure should be
// returned as a staged *Error so the proxy maps it to a sensible HTTP status; a
// plain error is treated as an upstream (502) failure.
type Resolver interface {
	Resolve(ctx context.Context, req wire.Request) (Candidates, error)
}

// Candidates is an ordered list of provider candidates to seal to, best first.
// The client tries them in order, re-sealing to the next when one fails
// (SPEC §4.4: sealed ciphertext is bound to one enclave's key, so a fallback
// must re-seal, not re-route).
//
// Materializing a candidate into a Provider may fetch its enc key from the
// broker, so it is deferred to Provider(i): the happy path (the head succeeds)
// never fetches keys for the tail.
type Candidates interface {
	// Len is the number of candidates; >= 1 whenever Resolve returns no error.
	Len() int
	// Provider materializes the i-th candidate (0 <= i < Len), fetching its enc
	// key if it is not already cached. Returning an error for one candidate lets
	// the client skip it and try the next, so an implementation should stage its
	// error like Resolve.
	Provider(ctx context.Context, i int) (Provider, error)
}

// staticResolver always returns the same single provider, ignoring the request —
// the low-level case for a caller that already holds a provider identity. It
// backs core.New and is used mainly by tests and any direct-seal-to-a-known-
// provider caller; the shipped server forms route instead (client/route).
type staticResolver struct{ provider Provider }

func (s staticResolver) Resolve(context.Context, wire.Request) (Candidates, error) {
	return staticCandidates{s.provider}, nil
}

// staticCandidates is a fixed candidate list — no lazy materialization, no
// fallback beyond the providers it already holds. A one-element list backs the
// static resolver.
type staticCandidates []Provider

func (s staticCandidates) Len() int { return len(s) }

func (s staticCandidates) Provider(_ context.Context, i int) (Provider, error) {
	return s[i], nil
}
