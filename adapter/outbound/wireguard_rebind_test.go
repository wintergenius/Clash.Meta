package outbound

import (
	"context"
	"errors"
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

type stubWireGuardDevice struct {
	events       []string
	bindUpdateFn func() error
}

func (d *stubWireGuardDevice) Close() {
	d.events = append(d.events, "close")
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

	if len(dev.events) != 2 || dev.events[0] != "bind_update" || dev.events[1] != "keepalive" {
		t.Fatalf("expected [bind_update keepalive], got %v", dev.events)
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

	if len(dev.events) != 1 || dev.events[0] != "bind_update" {
		t.Fatalf("expected only [bind_update] on error, got %v", dev.events)
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

	if len(dev.events) != 2 || dev.events[0] != "bind_update" || dev.events[1] != "keepalive" {
		t.Fatalf("expected forwarded [bind_update keepalive], got %v", dev.events)
	}
}
