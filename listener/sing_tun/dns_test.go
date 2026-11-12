package sing_tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/metacubex/sing/common/buf"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"

	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
)

type trackingCloseConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *trackingCloseConn) Close() error {
	c.closed.Store(true)
	return nil
}

func testTunHandler() *ListenerHandler {
	return &ListenerHandler{
		DnsAddrPorts: []netip.AddrPort{
			netip.MustParseAddrPort("0.0.0.0:53"),
			netip.MustParseAddrPort("198.18.0.2:53"),
			netip.MustParseAddrPort("[fdfe:dcba:9876::2]:53"),
		},
		Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")},
		Inet6Address: []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
	}
}

func TestShouldRejectLocalDoTPreservesStrictPrivateDnsAndFakeIPPool(t *testing.T) {
	h := testTunHandler()

	rejectCases := []string{
		"198.18.0.2:853",
		"198.18.0.1:853",
		"[fdfe:dcba:9876::2]:853",
		"[fdfe:dcba:9876::1]:853",
		"[::ffff:198.18.0.2]:853",
	}
	for _, raw := range rejectCases {
		if !h.ShouldRejectLocalDoT(netip.MustParseAddrPort(raw)) {
			t.Errorf("expected local TUN DoT probe %s to be rejected", raw)
		}
	}

	allowCases := []string{
		"198.18.0.2:53",    // standard DNS hijack port
		"198.18.0.4:853",   // first allocated FakeIP (Strict Private DNS e.g. dns.google)
		"198.18.0.15:853",  // allocated FakeIP
		"8.8.8.8:853",      // public DoT resolver
		"94.140.14.14:853", // AdGuard DoT resolver
		"[2001:4860:4860::8888]:853",
	}
	for _, raw := range allowCases {
		if h.ShouldRejectLocalDoT(netip.MustParseAddrPort(raw)) {
			t.Errorf("expected %s NOT to be rejected as local TUN DoT", raw)
		}
	}
}

func TestNewConnectionRejectsLocalDoTWithoutPreClosingConn(t *testing.T) {
	h := testTunHandler()
	conn := &trackingCloseConn{}
	meta := M.Metadata{
		Source:      M.ParseSocksaddr("198.18.0.1:41956"),
		Destination: M.ParseSocksaddr("198.18.0.2:853"),
	}

	err := h.NewConnection(context.Background(), conn, meta)
	if !errors.Is(err, errRejectLocalDoT) {
		t.Fatalf("expected errRejectLocalDoT, got %v", err)
	}
	if conn.closed.Load() {
		t.Fatal("NewConnection must NOT pre-close conn so sing-tun stacks emit TCP RST via Abort/SetLinger(0)")
	}
}

func TestNewConnectionClosesConnWhenAutoRedirectHandler(t *testing.T) {
	h := testTunHandler()
	h.ListenerHandler = &sing.ListenerHandler{ListenerConfig: sing.ListenerConfig{Type: C.REDIR}}
	conn := &trackingCloseConn{}
	meta := M.Metadata{
		Source:      M.ParseSocksaddr("198.18.0.1:41956"),
		Destination: M.ParseSocksaddr("198.18.0.2:853"),
	}

	err := h.NewConnection(context.Background(), conn, meta)
	if !errors.Is(err, errRejectLocalDoT) {
		t.Fatalf("expected errRejectLocalDoT, got %v", err)
	}
	if !conn.closed.Load() {
		t.Fatal("C.REDIR handler must close conn explicitly because sing-tun redirectServer ignores NewConnection errors")
	}
}

func TestNewPacketReleasesBufferOnLocalDoQDrop(t *testing.T) {
	h := testTunHandler()
	buffer := buf.NewPacket()
	buffer.WriteZeroN(16)
	meta := M.Metadata{
		Source:      M.ParseSocksaddr("198.18.0.1:50000"),
		Destination: M.ParseSocksaddr("198.18.0.2:853"),
	}

	initCalled := false
	h.NewPacket(context.Background(), meta.Source.AddrPort(), buffer, meta, func(network.PacketConn) network.PacketWriter {
		initCalled = true
		return nil
	})
	if initCalled {
		t.Fatal("expected local DoQ packet to be dropped without initializing NAT writer")
	}
}
