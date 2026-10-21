package valkeygcp

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/valkey-io/valkey-go"
)

// defaultUser is the AUTH user valkey-go uses when a credential has no username.
const defaultUser = "default"

// AuthEvent describes one credential hand-out to valkey-go (U9). valkey-go asks for
// credentials for every new connection (its HELLO) and at each proactive re-AUTH. An event
// never contains the token itself.
type AuthEvent struct {
	// Address is the node the credentials are for, "" if valkey-go didn't say.
	Address string
	// Username is the AUTH username; "default" for the default user.
	Username string
	// Fingerprint is the first 12 hex digits of the token's SHA-256, so a rotation shows up
	// as a new value. It is empty when no token is handed out (AUTH skipped, or Err set).
	Fingerprint string
	// RefreshAfter is when the next proactive re-AUTH is due; zero when none is scheduled.
	RefreshAfter time.Time
	// Fallback reports that a token fetch failed and the last-known-good token (or, once it
	// has expired, no token) was handed out instead (U6). OnCredentialError gets the error.
	Fallback bool
	// Plaintext reports that NewClient wired these credentials for connections without TLS:
	// the instance has in-transit encryption disabled, or TLS.Mode is TLSDisabled (U10). The
	// low-level options (WithIAMOptions, WithTokenAuth) don't know the transport and leave it
	// false.
	Plaintext bool
	// Err is set when no credentials could be handed out. valkey-go then fails the dial, or
	// closes the connection on a re-AUTH.
	Err error
}

// authEvent builds the event for one AuthCredentialsFn call.
func authEvent(c valkey.AuthCredentialsContext, user string, creds valkey.AuthCredentials, fallback, plaintext bool, err error) AuthEvent {
	if creds.Username != "" {
		user = creds.Username
	}
	if user == "" {
		user = defaultUser
	}
	ev := AuthEvent{Username: user, RefreshAfter: creds.RefreshAfter, Fallback: fallback, Plaintext: plaintext, Err: err}
	if c.Address != nil {
		ev.Address = c.Address.String()
	}
	if creds.Password != "" {
		sum := sha256.Sum256([]byte(creds.Password))
		ev.Fingerprint = hex.EncodeToString(sum[:6])
	}
	return ev
}

