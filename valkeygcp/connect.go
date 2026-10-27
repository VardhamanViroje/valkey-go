package valkeygcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/valkey-io/valkey-go"
)

// connect builds the valkey client. valkey-go dials InitAddress once and returns an ERR_IAM_*
// reply to HELLO as an error without retrying, so connect retries those with the backoff
// Google recommends for IAM backend errors. ctx bounds the retries, which also stop after
// setupTimeout when ctx has no earlier deadline. user names the AUTH user in error messages
// ("" when unknown).
func connect(ctx context.Context, opt valkey.ClientOption, user string) (valkey.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	var lastErr error
	for attempt := 0; ; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr == nil {
				return nil, err // valkey.NewClient takes no context
			}
			return nil, fmt.Errorf("valkeygcp: %w (gave up after %d attempts: %w)", lastErr, attempt, err)
		}
		client, err := valkey.NewClient(opt)
		if err == nil {
			return client, nil
		}
		if !isIAMBackendError(err) {
			return nil, explainHandshakeError(err, user)
		}
		lastErr = err
		t := time.NewTimer(iamBackoff(attempt))
		select {
		case <-ctx.Done():
			t.Stop()
		case <-t.C:
		}
	}
}

// explainHandshakeError adds a hint when an ACL rule refused CLIENT TRACKING, which
// valkey-go sends on every new connection unless ClientOption.DisableCache is set.
func explainHandshakeError(err error, user string) error {
	if errors.Is(err, valkey.ErrNoCache) && strings.Contains(err.Error(), "NOPERM") {
		return fmt.Errorf("valkeygcp: the ACL rule for %s must allow CLIENT TRACKING (+client|tracking), or set ClientOption.DisableCache: %w", who(user), err)
	}
	return err
}

// who names the AUTH user in error messages.
func who(user string) string {
	if user == "" {
		return "the connecting user"
	}
	return fmt.Sprintf("user %q", user)
}
