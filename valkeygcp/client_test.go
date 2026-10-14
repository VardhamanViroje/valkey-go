package valkeygcp

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valkey-io/valkey-go"
	"github.com/valkey-io/valkey-go/internal/cmds"
	"golang.org/x/oauth2"
)

// captureOption records the wired ClientOption and stops the constructor before it dials.
func captureOption(captured *valkey.ClientOption, errStop error) GCPOption {
	return func(_ context.Context, opt *valkey.ClientOption) error {
		*captured = *opt
		return errStop
	}
}

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

	var opt valkey.ClientOption
	errStop := errors.New("stop before dialing")
	if _, err := NewClusterClient(ctx, "10.0.0.15:6379", gcpOpt, captureOption(&opt, errStop)); !errors.Is(err, errStop) {
		t.Fatalf("got %v", err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.15:6379" || !opt.ClusterOption.PreferInitAddressRefresh ||
		!opt.ClusterOption.PreferClusterShards || opt.ClusterOption.ShardsRefreshInterval != defaultShardsRefreshInterval {
		t.Errorf("cluster options = %+v / %+v", opt.InitAddress, opt.ClusterOption)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "cluster-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

func TestNewClusterClient_OptionError(t *testing.T) {
	ctx := context.Background()
	errExpected := errors.New("custom option error")

	_, err := NewClusterClient(ctx, "127.0.0.1:6379", func(context.Context, *valkey.ClientOption) error {
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

	var opt valkey.ClientOption
	errStop := errors.New("stop before dialing")
	if _, err := NewStandaloneClient(ctx, "10.0.0.2:6379", "10.0.0.3:6379", gcpOpt, captureOption(&opt, errStop)); !errors.Is(err, errStop) {
		t.Fatalf("got %v", err)
	}
	if len(opt.InitAddress) != 1 || opt.InitAddress[0] != "10.0.0.2:6379" ||
		len(opt.Standalone.ReplicaAddress) != 1 || opt.Standalone.ReplicaAddress[0] != "10.0.0.3:6379" || opt.SendToReplicas == nil {
		t.Errorf("standalone options = %+v / %+v", opt.InitAddress, opt.Standalone)
	}
	creds, err := opt.AuthCredentialsFn(valkey.AuthCredentialsContext{})
	if err != nil || creds.Username != DefaultIAMUsername || creds.Password != "standalone-token" {
		t.Fatalf("creds = %+v, %v", creds, err)
	}
}

func TestNewStandaloneClient_OptionError(t *testing.T) {
	ctx := context.Background()
	errExpected := errors.New("standalone option error")

	_, err := NewStandaloneClient(ctx, "127.0.0.1:6379", "127.0.0.1:6380", func(context.Context, *valkey.ClientOption) error {
		return errExpected
	})
	if !errors.Is(err, errExpected) {
		t.Fatalf("expected error %v, got %v", errExpected, err)
	}
}

func TestNewStandaloneClient_SendToReplicasLogic(t *testing.T) {
	var capturedOpt valkey.ClientOption
	captureOpt := func(_ context.Context, opt *valkey.ClientOption) error {
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
		err := construct(func(_ context.Context, opt *valkey.ClientOption) error {
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

// T-CTX-1: options get the constructor's ctx, and a ctx that ends during setup stops the
// constructor before it dials (valkey.NewClient takes no context).
func TestConstructors_PassContextToOptions(t *testing.T) {
	type key struct{}
	errStop := errors.New("stop before dialing")
	for name, construct := range map[string]func(context.Context, GCPOption) error{
		"cluster": func(ctx context.Context, o GCPOption) error {
			_, err := NewClusterClient(ctx, "127.0.0.1:0", o)
			return err
		},
		"standalone": func(ctx context.Context, o GCPOption) error {
			_, err := NewStandaloneClient(ctx, "127.0.0.1:0", "127.0.0.1:0", o)
			return err
		},
	} {
		var got any
		err := construct(context.WithValue(context.Background(), key{}, "caller"), func(ctx context.Context, _ *valkey.ClientOption) error {
			got = ctx.Value(key{})
			return errStop
		})
		if !errors.Is(err, errStop) || got != "caller" {
			t.Fatalf("%s: option saw ctx value %v (err %v), want the constructor's ctx", name, got, err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		err = construct(ctx, func(context.Context, *valkey.ClientOption) error {
			cancel() // e.g. the caller's deadline passes during setup
			return nil
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s: got %v, want context.Canceled before dialing", name, err)
		}
	}
}

// T-CTX-2: missing ADC fails setup with the real error, before any dial.
func TestWithDefaultIAM(t *testing.T) {
	// A credentials file that doesn't exist makes ADC fail at once, without probing the
	// metadata server, so the result is the same on laptops, CI and Google Cloud.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	opt := valkey.ClientOption{}
	err := WithDefaultIAM()(context.Background(), &opt)
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("got %v, want the ADC error", err)
	}
	if opt.AuthCredentialsFn != nil {
		t.Error("AuthCredentialsFn set even though setup failed")
	}
	_, err = NewClusterClient(context.Background(), "127.0.0.1:0", WithDefaultIAM())
	if err == nil || !strings.Contains(err.Error(), "Application Default Credentials not found") {
		t.Fatalf("NewClusterClient: got %v, want the ADC error", err)
	}
}
