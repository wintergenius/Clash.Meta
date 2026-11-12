package outboundgroup

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/common/utils"
)

const postRoamIdleWindow = 2 * time.Minute

type recentlyActiveProvider interface {
	RecentlyActive(window time.Duration) bool
}

func (gb *GroupBase) hasRecentActivity(window time.Duration) bool {
	for _, pd := range gb.providers {
		if active, ok := pd.(recentlyActiveProvider); ok && active.RecentlyActive(window) {
			return true
		}
	}
	return false
}

func runPostRoamGroupProbe(
	ctx context.Context,
	gb *GroupBase,
	testUrl string,
	expectedStatusRaw string,
	fastTimeout time.Duration,
	force bool,
	nowFn func() string,
	onFinish func(),
) (movedFrom string, movedTo string, changed bool) {
	if onFinish != nil {
		defer onFinish()
	}
	testUrl = strings.TrimSpace(testUrl)
	if testUrl == "" || ctx.Err() != nil {
		return "", "", false
	}
	proxies := gb.GetProxies(false)
	if len(proxies) <= 1 {
		return "", "", false
	}
	if !force && !gb.hasRecentActivity(postRoamIdleWindow) {
		return "", "", false
	}

	before := nowFn()
	fullTimeout := time.Duration(gb.testTimeout) * time.Millisecond
	if fullTimeout <= 0 {
		fullTimeout = 5 * time.Second
	}
	if fastTimeout <= 0 || fastTimeout > fullTimeout {
		fastTimeout = fullTimeout
	}

	expectedStatus, _ := utils.NewUnsignedRanges[uint16](expectedStatusRaw)
	fullCtx, cancelFull := context.WithTimeout(ctx, fullTimeout)
	defer cancelFull()
	probeCtx, cancelFast := context.WithCancelCause(fullCtx)
	defer cancelFast(nil)

	var (
		anyAlive    atomic.Bool
		fastElapsed atomic.Bool
	)
	if fastTimeout < fullTimeout {
		timer := time.AfterFunc(fastTimeout, func() {
			fastElapsed.Store(true)
			if anyAlive.Load() {
				cancelFast(context.DeadlineExceeded)
			}
		})
		defer timer.Stop()
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	for _, proxy := range proxies {
		p := proxy
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-probeCtx.Done():
				return
			}
			_, err := p.URLTest(probeCtx, testUrl, expectedStatus)
			if err == nil && p.AliveForTestUrl(testUrl) {
				anyAlive.Store(true)
				if fastElapsed.Load() {
					cancelFast(context.DeadlineExceeded)
				}
			}
		}()
	}
	wg.Wait()

	if ctx.Err() != nil {
		return "", "", false
	}
	if onFinish != nil {
		onFinish()
	}
	after := nowFn()
	return before, after, anyAlive.Load() && before != "" && after != "" && before != after
}

// PostRoamCheck probes a Fallback group's members after a network switch. Once
// at least one backup member responds, any primary still hanging past
// fastTimeout is marked dead immediately instead of stalling traffic for the
// full 6s health-check timeout.
func (f *Fallback) PostRoamCheck(ctx context.Context, fastTimeout time.Duration, force bool) (string, string, bool) {
	return runPostRoamGroupProbe(ctx, f.GroupBase, f.testUrl, f.expectedStatus, fastTimeout, force, f.Now, nil)
}

// PostRoamCheck resets URLTest's cached pick and probes group members after a
// network switch using the same fast-failover budget as Fallback.
func (u *URLTest) PostRoamCheck(ctx context.Context, fastTimeout time.Duration, force bool) (string, string, bool) {
	u.fastSingle.Reset()
	return runPostRoamGroupProbe(ctx, u.GroupBase, u.testUrl, u.expectedStatus, fastTimeout, force, u.Now, u.fastSingle.Reset)
}
