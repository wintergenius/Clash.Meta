package tunnel_test

import (
	"encoding/base64"
	"testing"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/tunnel"
)

type countingRebindAdapter struct {
	outbound.ProxyAdapter
	rebinds int
	closes  int
}

func (a *countingRebindAdapter) Rebind() {
	a.rebinds++
}

func (a *countingRebindAdapter) Close() error {
	a.closes++
	return nil
}

type stubProxyProvider struct {
	name    string
	proxies []C.Proxy
}

func (p *stubProxyProvider) Name() string                  { return p.name }
func (p *stubProxyProvider) VehicleType() P.VehicleType    { return P.Compatible }
func (p *stubProxyProvider) Type() P.ProviderType          { return P.Proxy }
func (p *stubProxyProvider) Initial() error                { return nil }
func (p *stubProxyProvider) Update() error                 { return nil }
func (p *stubProxyProvider) Proxies() []C.Proxy            { return p.proxies }
func (p *stubProxyProvider) Count() int                    { return len(p.proxies) }
func (p *stubProxyProvider) Touch()                        {}
func (p *stubProxyProvider) HealthCheck()                  {}
func (p *stubProxyProvider) Version() uint32               { return 1 }
func (p *stubProxyProvider) HealthCheckURL() string        { return "" }
func (p *stubProxyProvider) RegisterHealthCheckTask(string, utils.IntRanges[uint16], string, uint) {
}

func TestResetWireGuardBindsDeduplicatesAndUnwrapsAdapters(t *testing.T) {
	sharedInner := &countingRebindAdapter{ProxyAdapter: outbound.NewDirect()}
	wrappedShared := outbound.NewAutoCloseProxyAdapter(sharedInner)
	defer func() { _ = wrappedShared.Close() }()

	providerInner := &countingRebindAdapter{ProxyAdapter: outbound.NewDirect()}
	wrappedProvider := outbound.NewAutoCloseProxyAdapter(providerInner)
	defer func() { _ = wrappedProvider.Close() }()

	// Real YAML-parsed WireGuard proxy (uninitialized): must expose Rebind()
	// through adapter.ParseProxy -> autoCloseProxyAdapter -> adapter.NewProxy
	// without crashing or initializing idle sockets.
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	parsedWG, err := adapter.ParseProxy(map[string]any{
		"name":        "parsed-wg",
		"type":        "wireguard",
		"server":      "198.51.100.1",
		"port":        51820,
		"ip":          "10.10.0.2/32",
		"private-key": key,
		"public-key":  key,
		"udp":         true,
	})
	if err != nil {
		t.Fatalf("ParseProxy wireguard failed: %v", err)
	}
	defer func() { _ = parsedWG.Close() }()
	if _, ok := parsedWG.Adapter().(interface{ Rebind() }); !ok {
		t.Fatalf("expected ParseProxy wireguard adapter %T to implement Rebind()", parsedWG.Adapter())
	}

	sharedProxyA := adapter.NewProxy(wrappedShared)
	sharedProxyB := adapter.NewProxy(wrappedShared)
	providerProxy := adapter.NewProxy(wrappedProvider)

	tunnel.UpdateProxies(
		map[string]C.Proxy{
			"shared-a":  sharedProxyA,
			"parsed-wg": parsedWG,
		},
		map[string]P.ProxyProvider{
			"prov": &stubProxyProvider{
				name:    "prov",
				proxies: []C.Proxy{sharedProxyB, providerProxy},
			},
		},
	)
	defer tunnel.UpdateProxies(map[string]C.Proxy{}, nil)

	tunnel.ResetWireGuardBinds()

	if sharedInner.rebinds != 1 {
		t.Fatalf("expected shared adapter to be rebound once, got %d", sharedInner.rebinds)
	}
	if providerInner.rebinds != 1 {
		t.Fatalf("expected provider adapter to be rebound once, got %d", providerInner.rebinds)
	}
}

func TestUpdateProxiesClosesReplacedOutboundsOnly(t *testing.T) {
	keptInner := &countingRebindAdapter{ProxyAdapter: outbound.NewDirect()}
	replacedInner := &countingRebindAdapter{ProxyAdapter: outbound.NewDirect()}
	keptProxy := adapter.NewProxy(keptInner)
	replacedProxy := adapter.NewProxy(replacedInner)

	tunnel.UpdateProxies(map[string]C.Proxy{
		"kept":     keptProxy,
		"replaced": replacedProxy,
	}, nil)

	freshInner := &countingRebindAdapter{ProxyAdapter: outbound.NewDirect()}
	tunnel.UpdateProxies(map[string]C.Proxy{
		"kept":     keptProxy,
		"replaced": adapter.NewProxy(freshInner),
	}, nil)
	defer tunnel.UpdateProxies(map[string]C.Proxy{}, nil)

	if keptInner.closes != 0 {
		t.Fatalf("expected kept proxy not to be closed, got %d", keptInner.closes)
	}
	if replacedInner.closes != 1 {
		t.Fatalf("expected replaced proxy to be closed once, got %d", replacedInner.closes)
	}
}
