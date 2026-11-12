package outbound

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/metacubex/mihomo/constant"
)

type stubWireGuardDevice struct {
	events       []string
	upFn         func() error
	bindUpdateFn func() error
	reinitFn     func(string) error
}

func (d *stubWireGuardDevice) Close() {
	d.events = append(d.events, "close")
}

func (d *stubWireGuardDevice) Up() error {
	d.events = append(d.events, "up")
	if d.upFn != nil {
		return d.upFn()
	}
	return nil
}

func (d *stubWireGuardDevice) IpcSet(string) error {
	d.events = append(d.events, "ipc_set")
	return nil
}

func (d *stubWireGuardDevice) BindUpdate() error {
	d.events = append(d.events, "bind_update")
	if d.bindUpdateFn != nil {
		return d.bindUpdateFn()
	}
	return nil
}

func (d *stubWireGuardDevice) SendKeepalivesToPeersWithCurrentKeypair() {
	d.events = append(d.events, "keepalive")
}

func (d *stubWireGuardDevice) ReinitiatePeerHandshake(hexKey string) error {
	d.events = append(d.events, "reinit:"+hexKey)
	if d.reinitFn != nil {
		return d.reinitFn(hexKey)
	}
	return nil
}

func newTestWireGuard(dev wireguardGoDevice, initialized bool) (*WireGuard, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := &WireGuard{
		Base: NewBase(BaseOption{
			Name: "test-wg",
			Addr: "198.51.100.10:51820",
			Type: C.WireGuard,
			UDP:  true,
		}),
		device:    dev,
		runCtx:    ctx,
		runCancel: cancel,
	}
	wg.initOk.Store(initialized)
	return wg, cancel
}

func TestWireGuardRebindSkipsUninitializedOutbound(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, cancel := newTestWireGuard(dev, false)
	defer cancel()

	wg.Rebind()

	if len(dev.events) != 0 {
		t.Fatalf("expected uninitialized outbound not to touch device, got %v", dev.events)
	}
}

func TestWireGuardRebindUpdatesBindAndSendsKeepalive(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, cancel := newTestWireGuard(dev, true)
	defer cancel()

	wg.Rebind()

	want := []string{"up", "bind_update", "keepalive"}
	if len(dev.events) != len(want) || dev.events[0] != want[0] || dev.events[1] != want[1] || dev.events[2] != want[2] {
		t.Fatalf("expected %v, got %v", want, dev.events)
	}
}

func TestWireGuardRebindDoesNotSendKeepaliveOnBindError(t *testing.T) {
	dev := &stubWireGuardDevice{
		bindUpdateFn: func() error {
			return errors.New("network unreachable")
		},
	}
	wg, cancel := newTestWireGuard(dev, true)
	defer cancel()

	wg.Rebind()

	if len(dev.events) != 2 || dev.events[0] != "up" || dev.events[1] != "bind_update" {
		t.Fatalf("expected [up bind_update] on error, got %v", dev.events)
	}
}

func TestWireGuardRebindSkipsClosedOutbound(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, _ := newTestWireGuard(dev, true)

	if err := wg.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}
	dev.events = nil

	wg.Rebind()

	if len(dev.events) != 0 {
		t.Fatalf("expected closed outbound not to rebind, got %v", dev.events)
	}
}

func TestAutoCloseProxyAdapterForwardsRebind(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, cancel := newTestWireGuard(dev, true)
	defer cancel()

	wrapped := NewAutoCloseProxyAdapter(wg)
	defer func() { _ = wrapped.Close() }()

	rebinder, ok := wrapped.(interface{ Rebind() })
	if !ok {
		t.Fatalf("expected NewAutoCloseProxyAdapter to expose Rebind()")
	}
	rebinder.Rebind()

	if len(dev.events) != 3 || dev.events[0] != "up" || dev.events[1] != "bind_update" || dev.events[2] != "keepalive" {
		t.Fatalf("expected forwarded [up bind_update keepalive], got %v", dev.events)
	}
}

func TestAmneziaWGRebindForcesHandshakeOnlyWhenRecentlyActive(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, cancel := newTestWireGuard(dev, true)
	defer cancel()

	hexKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	wg.option.AmneziaWGOption = &AmneziaWGOption{Version: 3}
	wg.option.PublicKey = hexKey
	wg.lastActiveNano.Store(time.Now().UnixNano())

	wg.Rebind()
	if len(dev.events) != 3 || dev.events[2] != "reinit:"+hexKey {
		t.Fatalf("expected active AmneziaWG rebind to force handshake, got %v", dev.events)
	}

	// Simulate an outbound that has been idle beyond wgActiveRoamWindow.
	dev.events = nil
	wg.lastActiveNano.Store(time.Now().Add(-(wgActiveRoamWindow + time.Minute)).UnixNano())
	wg.Rebind()
	if len(dev.events) != 3 || dev.events[2] != "keepalive" {
		t.Fatalf("expected idle AmneziaWG rebind to send lightweight keepalive, got %v", dev.events)
	}
}

func TestAmneziaWGRebindEnforcesMinHandshakeGap(t *testing.T) {
	dev := &stubWireGuardDevice{}
	wg, cancel := newTestWireGuard(dev, true)
	defer cancel()

	wg.option.AmneziaWGOption = &AmneziaWGOption{Version: 3}
	wg.option.PublicKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	wg.lastActiveNano.Store(time.Now().UnixNano())

	wg.Rebind()
	start := time.Now()
	wg.Rebind()
	elapsed := time.Since(start)
	if elapsed < wgMinRebindHandshakeGap-5*time.Millisecond {
		t.Fatalf("expected back-to-back Rebind to wait at least ~%v, took %v", wgMinRebindHandshakeGap, elapsed)
	}
}

type fakeCDialer struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (f *fakeCDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	f.calls.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if f.fail.Load() {
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("network is unreachable")}
	}
	c1, c2 := net.Pipe()
	_ = c2.Close()
	return c1, nil
}

func (f *fakeCDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("unused")
}

func TestWGBindDialerBackoffResetAndErrClosedWrap(t *testing.T) {
	base := &fakeCDialer{}
	base.fail.Store(true)
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()

	bd := newWGBindDialer(base, runCtx)

	// First failure returns immediately with no sleep.
	t0 := time.Now()
	if _, err := bd.DialContext(context.Background(), "udp", "198.51.100.1:51820"); err == nil {
		t.Fatal("expected dial error")
	}
	if d := time.Since(t0); d > 40*time.Millisecond {
		t.Fatalf("first failure should not sleep, took %v", d)
	}

	// Second failure waits ~100ms backoff.
	t1 := time.Now()
	if _, err := bd.DialContext(context.Background(), "udp", "198.51.100.1:51820"); err == nil {
		t.Fatal("expected second dial error")
	}
	if d := time.Since(t1); d < 80*time.Millisecond {
		t.Fatalf("second failure should throttle (~100ms), took %v", d)
	}

	// Reset clears accumulated backoff so a new route connects in ~0ms.
	bd.Reset()
	base.fail.Store(false)
	t2 := time.Now()
	conn, err := bd.DialContext(nil, "udp", "198.51.100.1:51820") // also exercises nil ctx normalization
	if err != nil {
		t.Fatalf("expected immediate success after Reset(), got %v", err)
	}
	_ = conn.Close()
	if d := time.Since(t2); d > 40*time.Millisecond {
		t.Fatalf("dial after Reset() paid stale backoff: %v", d)
	}

	// Context cancellation during retry wraps net.ErrClosed to avoid 333ms deathSpiral.
	base.fail.Store(true)
	_, _ = bd.DialContext(context.Background(), "udp", "198.51.100.1:51820")
	bindCtx, bindCancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(15 * time.Millisecond)
		bindCancel()
	}()
	_, err = bd.DialContext(bindCtx, "udp", "198.51.100.1:51820")
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("expected canceled bind dial to wrap net.ErrClosed, got %v", err)
	}
}

func TestTransientWireGuardSocketErrorClassification(t *testing.T) {
	opErr := &net.OpError{Op: "write", Net: "udp", Err: errors.New("sendto: network is unreachable")}
	if !isTransientWireGuardSocketError(opErr) {
		t.Fatal("expected *net.OpError to be classified as transient")
	}
	if isTransientWireGuardSocketError(errors.New("invalid public key hex")) {
		t.Fatal("expected config/crypto error not to be classified as transient")
	}
}
