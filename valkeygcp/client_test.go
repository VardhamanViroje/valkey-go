package valkeygcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
	"golang.org/x/oauth2"
)

func TestNewClusterClient_OptionWiring(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "cluster-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	gcpOpt := WithIAMOptions(IAMAuthOptions{
		CustomTokenSource: mock,
	})

	client, err := NewClusterClient(ctx, "127.0.0.1:0", gcpOpt)
	if err == nil && client != nil {
		client.Close()
	}
}

func TestNewClusterClient_OptionError(t *testing.T) {
	ctx := context.Background()
	errExpected := errors.New("custom option error")

	_, err := NewClusterClient(ctx, "127.0.0.1:6379", func(opt *valkey.ClientOption) error {
		return errExpected
	})
	if !errors.Is(err, errExpected) {
		t.Fatalf("expected error %v, got %v", errExpected, err)
	}
}

func TestNewStandaloneClient_OptionWiring(t *testing.T) {
	ctx := context.Background()
	mock := &mockTokenSource{
		defaultTok: &oauth2.Token{
			AccessToken: "standalone-token",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(1 * time.Hour),
		},
	}

	gcpOpt := WithIAMOptions(IAMAuthOptions{
		CustomTokenSource: mock,
	})

	client, err := NewStandaloneClient(ctx, "127.0.0.1:0", "127.0.0.1:0", gcpOpt)
	if err == nil && client != nil {
		client.Close()
	}
}

func TestNewStandaloneClient_OptionError(t *testing.T) {
	ctx := context.Background()
	errExpected := errors.New("standalone option error")

	_, err := NewStandaloneClient(ctx, "127.0.0.1:6379", "127.0.0.1:6380", func(opt *valkey.ClientOption) error {
		return errExpected
	})
	if !errors.Is(err, errExpected) {
		t.Fatalf("expected error %v, got %v", errExpected, err)
	}
}

func TestNewStandaloneClient_SendToReplicasLogic(t *testing.T) {
	var capturedOpt valkey.ClientOption
	captureOpt := func(opt *valkey.ClientOption) error {
		capturedOpt = *opt
		return nil
	}

	ctx := context.Background()
	_, _ = NewStandaloneClient(ctx, "127.0.0.1:0", "127.0.0.1:0", captureOpt)

	if capturedOpt.SendToReplicas == nil {
		t.Fatal("expected SendToReplicas to be configured")
	}

	builder := cmds.NewBuilder(cmds.NoSlot)

	// Read-only command (GET) -> should route to replica
	getCmd := builder.Get().Key("k").Build()
	if !capturedOpt.SendToReplicas(getCmd) {
		t.Errorf("expected GET to route to replica, got false")
	}

	// Write command (SET) -> should NOT route to replica
	setCmd := builder.Set().Key("k").Value("v").Build()
	if capturedOpt.SendToReplicas(setCmd) {
		t.Errorf("expected SET NOT to route to replica, got true")
	}

	// Blocking command (BLPOP) -> should NOT route to replica even if read-only
	blpopCmd := builder.Blpop().Key("k").Timeout(1).Build()
	if capturedOpt.SendToReplicas(blpopCmd) {
		t.Errorf("expected BLPOP NOT to route to replica, got true")
	}
}

func TestConstructors_MemorystoreRetryDelay(t *testing.T) {
	errStop := errors.New("stop before dialing")
	for name, construct := range map[string]func(GCPOption) error{
		"cluster": func(o GCPOption) error {
			_, err := NewClusterClient(context.Background(), "127.0.0.1:0", o)
			return err
		},
		"standalone": func(o GCPOption) error {
			_, err := NewStandaloneClient(context.Background(), "127.0.0.1:0", "127.0.0.1:0", o)
			return err
		},
	} {
		var captured valkey.ClientOption
		err := construct(func(opt *valkey.ClientOption) error {
			captured = *opt
			return errStop
		})
		if !errors.Is(err, errStop) {
			t.Fatalf("%s: got %v", name, err)
		}
		if captured.RetryDelay == nil || captured.RetryDelay(maxRetryAttempts, valkey.Completed{}, nil) >= 0 {
			t.Errorf("%s: RetryDelay is not memorystoreRetryDelay", name)
		}
	}
}

func TestWithDefaultIAM(t *testing.T) {
	opt := valkey.ClientOption{}
	gcpOpt := WithDefaultIAM()
	// In CI / local environment without ADC credentials, this should safely return an error
	// or configure AuthCredentialsFn if local ADC is present
	_ = gcpOpt(&opt)
}
