package outboundgroup

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	P "github.com/metacubex/mihomo/constant/provider"

	"github.com/stretchr/testify/require"
)

type delayedProxyAdapter struct {
	*outbound.Base
	delay        time.Duration
	hang         bool
	overrideAddr string
	dials        atomic.Int32
}

func newDelayedProxy(name string, delay time.Duration, hang bool) (*delayedProxyAdapter, C.Proxy) {
	ad := &delayedProxyAdapter{
		Base:  outbound.NewBase(outbound.BaseOption{Name: name, Type: C.Direct, UDP: true}),
		delay: delay,
		hang:  hang,
	}
	return ad, adapter.NewProxy(ad)
}

func (d *delayedProxyAdapter) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	d.dials.Add(1)
	if d.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if d.delay > 0 {
		timer := time.NewTimer(d.delay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		}
	}
	target := metadata.RemoteAddress()
	if d.overrideAddr != "" {
		target = d.overrideAddr
	}
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, err
	}
	return outbound.NewConn(conn, d), nil
}

type activityStubProvider struct {
	fakeProvider
	active bool
}

func (p *activityStubProvider) RecentlyActive(time.Duration) bool {
	return p.active
}

func TestFallbackPostRoamCheckCutsDeadPrimaryAtFastTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, deadPrimary := newDelayedProxy("FI", 0, true)
	_, liveBackup := newDelayedProxy("LV", 15*time.Millisecond, false)

	group, err := NewFallback(
		GroupCommonOption{
			Name:        "auto",
			URL:         server.URL,
			TestTimeout: 5000,
		},
		FallbackOption{},
		namedProxy("COMPATIBLE"),
		[]P.ProxyProvider{&activityStubProvider{
			fakeProvider: fakeProvider{name: "p", proxies: []C.Proxy{deadPrimary, liveBackup}},
			active:       true,
		}},
	)
	require.NoError(t, err)
	require.Equal(t, "FI", group.Now())

	start := time.Now()
	from, to, changed := group.PostRoamCheck(context.Background(), 120*time.Millisecond, false)
	elapsed := time.Since(start)

	require.True(t, changed)
	require.Equal(t, "FI", from)
	require.Equal(t, "LV", to)
	require.Equal(t, "LV", group.Now())
	require.Less(t, elapsed, time.Second, "fast failover must not wait out the full 5s TestTimeout")
}

func TestFallbackPostRoamCheckWaitsPastFastTimeoutWhenAllNodesAreSlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, deadPrimary := newDelayedProxy("FI", 0, true)
	_, slowLiveBackup := newDelayedProxy("LV", 160*time.Millisecond, false)

	group, err := NewFallback(
		GroupCommonOption{
			Name:        "auto",
			URL:         server.URL,
			TestTimeout: 3000,
		},
		FallbackOption{},
		namedProxy("COMPATIBLE"),
		[]P.ProxyProvider{&activityStubProvider{
			fakeProvider: fakeProvider{name: "p", proxies: []C.Proxy{deadPrimary, slowLiveBackup}},
			active:       true,
		}},
	)
	require.NoError(t, err)

	from, to, changed := group.PostRoamCheck(context.Background(), 60*time.Millisecond, false)
	require.True(t, changed)
	require.Equal(t, "FI", from)
	require.Equal(t, "LV", to)
	require.True(t, slowLiveBackup.AliveForTestUrl(server.URL))
}

func TestFallbackPostRoamCheckSkipsIdleLazyGroupInDoze(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	adA, proxyA := newDelayedProxy("FI", 0, false)
	adB, proxyB := newDelayedProxy("LV", 0, false)

	group, err := NewFallback(
		GroupCommonOption{Name: "auto", URL: server.URL, TestTimeout: 2000},
		FallbackOption{},
		namedProxy("COMPATIBLE"),
		[]P.ProxyProvider{&activityStubProvider{
			fakeProvider: fakeProvider{name: "p", proxies: []C.Proxy{proxyA, proxyB}},
			active:       false,
		}},
	)
	require.NoError(t, err)

	_, _, changed := group.PostRoamCheck(context.Background(), 100*time.Millisecond, false)
	require.False(t, changed)
	require.Equal(t, int32(0), adA.dials.Load())
	require.Equal(t, int32(0), adB.dials.Load())
}

func TestCanceledURLTestDoesNotClobberAliveState(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	_, hangProxy := newDelayedProxy("FI", 0, true)
	require.True(t, hangProxy.AliveForTestUrl(server.URL))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := hangProxy.URLTest(ctx, server.URL, nil)
	require.True(t, errors.Is(err, context.Canceled))
	require.True(t, hangProxy.AliveForTestUrl(server.URL), "explicit cancellation must not mark a live node dead")
}

func TestFallbackPostRoamCheckIgnoresBadHTTPStatusWhenExpectedStatusSet(t *testing.T) {
	goodServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer goodServer.Close()

	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer badServer.Close()

	badAd, badPrimary := newDelayedProxy("FI", 0, false)
	badAd.overrideAddr = badServer.Listener.Addr().String()
	_, slowLiveBackup := newDelayedProxy("LV", 140*time.Millisecond, false)

	group, err := NewFallback(
		GroupCommonOption{
			Name:           "auto",
			URL:            goodServer.URL,
			ExpectedStatus: "204",
			TestTimeout:    3000,
		},
		FallbackOption{},
		namedProxy("COMPATIBLE"),
		[]P.ProxyProvider{&activityStubProvider{
			fakeProvider: fakeProvider{name: "p", proxies: []C.Proxy{badPrimary, slowLiveBackup}},
			active:       true,
		}},
	)
	require.NoError(t, err)

	from, to, changed := group.PostRoamCheck(context.Background(), 50*time.Millisecond, false)
	require.True(t, changed, "502 response must not trigger fast-cancel before slow 204 backup finishes")
	require.Equal(t, "FI", from)
	require.Equal(t, "LV", to)
	require.False(t, badPrimary.AliveForTestUrl(goodServer.URL))
	require.True(t, slowLiveBackup.AliveForTestUrl(goodServer.URL))
}
