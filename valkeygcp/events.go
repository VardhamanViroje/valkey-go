package valkeygcp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
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
	// Fingerprint is 12 hex digits of an HMAC-SHA256 of the token, so a rotation shows up as
	// a new value. The HMAC key is random per process: unlike a plain hash, a logged
	// fingerprint can't be used to check guesses of a weak token offline, and fingerprints
	// only compare within one process. It is empty when no token is handed out (AUTH
	// skipped, or Err set).
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
		ev.Fingerprint = fingerprint(creds.Password)
	}
	return ev
}

// fingerprintKey is the HMAC key behind AuthEvent.Fingerprint. It is made on first use and
// never leaves the process.
var fingerprintKey = sync.OnceValue(func() []byte {
	key := make([]byte, sha256.Size)
	rand.Read(key) // never returns an error; crypto/rand crashes the program instead
	return key
})

// fingerprint returns the AuthEvent.Fingerprint of token.
func fingerprint(token string) string {
	mac := hmac.New(sha256.New, fingerprintKey())
	mac.Write([]byte(token))
	return hex.EncodeToString(mac.Sum(nil)[:6])
}

