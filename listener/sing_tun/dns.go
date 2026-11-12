package sing_tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"

	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

const dotPort = 853

var errRejectLocalDoT = errors.New("reject DoT/DoQ probe to local TUN address")

func (h *ListenerHandler) ShouldHijackDns(targetAddr netip.AddrPort) bool {
	for _, addrPort := range h.DnsAddrPorts {
		if addrPort == targetAddr || (addrPort.Addr().IsUnspecified() && targetAddr.Port() == 53) {
			return true
		}
	}
	return false
}

// ShouldRejectLocalDoT matches Opportunistic Private DNS probes (:853) aimed
// solely at the local TUN subnet (/30 IPv4, /126 IPv6) or explicit local TUN
// DNS addresses, while leaving Strict Private DNS (FakeIP >= .4 or public IPs)
// completely untouched.
func (h *ListenerHandler) ShouldRejectLocalDoT(targetAddr netip.AddrPort) bool {
	if targetAddr.Port() != dotPort {
		return false
	}
	addr := targetAddr.Addr().Unmap()
	if !addr.IsValid() {
		return false
	}
	for _, prefix := range h.Inet4Address {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, prefix := range h.Inet6Address {
		if prefix.Contains(addr) {
			return true
		}
	}
	for _, addrPort := range h.DnsAddrPorts {
		dnsAddr := addrPort.Addr().Unmap()
		if dnsAddr.IsValid() && !dnsAddr.IsUnspecified() && dnsAddr == addr {
			return true
		}
	}
	return false
}

func (h *ListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	target := metadata.Destination.AddrPort()
	if h.ShouldHijackDns(target) {
		log.Debugln("[DNS] hijack tcp:%s", metadata.Destination.String())
		return resolver.RelayDnsConn(ctx, conn, resolver.DefaultDnsReadTimeout)
	}
	if h.ShouldRejectLocalDoT(target) {
		// For TUN stacks (C.TUN), return non-nil error WITHOUT calling conn.Close()
		// so gvisor (endpoint.Abort) and mipstack/system/mixed (SetLinger(0)) emit
		// an immediate TCP RST instead of a graceful FIN. For Linux auto-redirect
		// (C.REDIR), sing-tun's redirectServer ignores NewConnection's error return
		// and does not close conn, so close with SO_LINGER=0 explicitly there.
		log.Debugln("[DNS] reject local DoT tcp:%s", metadata.Destination.String())
		if h.ListenerHandler != nil && h.Type == C.REDIR {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
		}
		return errRejectLocalDoT
	}
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (h *ListenerHandler) NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn network.PacketConn) network.PacketWriter) {
	target := metadata.Destination.AddrPort()
	if h.ShouldHijackDns(target) {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		writer := init(nil)
		rwOptions := network.ReadWaitOptions{
			FrontHeadroom: network.CalculateFrontHeadroom(writer),
			RearHeadroom:  network.CalculateRearHeadroom(writer),
			MTU:           resolver.SafeDnsPacketSize,
		}
		go relayDnsPacket(ctx, buffer, rwOptions, metadata.Destination, nil, &writer)
		return
	}
	if h.ShouldRejectLocalDoT(target) {
		log.Debugln("[DNS] drop local DoQ udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		buffer.Release()
		return
	}
	h.ListenerHandler.NewPacket(ctx, key, buffer, metadata, init)
}

func (h *ListenerHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	target := metadata.Destination.AddrPort()
	if h.ShouldHijackDns(target) {
		log.Debugln("[DNS] hijack udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		defer func() { _ = conn.Close() }()
		mutex := sync.Mutex{}
		var writer network.PacketWriter = conn // a new interface to set nil in defer
		defer func() {
			mutex.Lock() // this goroutine must exit after all conn.WritePacket() is not running
			defer mutex.Unlock()
			writer = nil
		}()
		rwOptions := network.ReadWaitOptions{
			FrontHeadroom: network.CalculateFrontHeadroom(conn),
			RearHeadroom:  network.CalculateRearHeadroom(conn),
			MTU:           resolver.SafeDnsPacketSize,
		}
		readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
		if isReadWaiter {
			readWaiter.InitializeReadWaiter(rwOptions)
		}
		for {
			var (
				readBuff *buf.Buffer
				dest     M.Socksaddr
				err      error
			)
			_ = conn.SetReadDeadline(time.Now().Add(resolver.DefaultDnsReadTimeout))
			readBuff = nil // clear last loop status, avoid repeat release
			if isReadWaiter {
				readBuff, dest, err = readWaiter.WaitReadPacket()
			} else {
				readBuff = rwOptions.NewPacketBuffer()
				dest, err = conn.ReadPacket(readBuff)
				if readBuff != nil {
					rwOptions.PostReturn(readBuff)
				}
			}
			if err != nil {
				if readBuff != nil {
					readBuff.Release()
				}
				if sing.ShouldIgnorePacketError(err) {
					break
				}
				return err
			}
			go relayDnsPacket(ctx, readBuff, rwOptions, dest, &mutex, &writer)
		}
		return nil
	}
	if h.ShouldRejectLocalDoT(target) {
		log.Debugln("[DNS] reject local DoQ udp:%s from %s", metadata.Destination.String(), metadata.Source.String())
		_ = conn.Close()
		return errRejectLocalDoT
	}
	return h.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}

func relayDnsPacket(ctx context.Context, readBuff *buf.Buffer, rwOptions network.ReadWaitOptions, dest M.Socksaddr, mutex *sync.Mutex, writer *network.PacketWriter) {
	ctx, cancel := context.WithTimeout(ctx, resolver.DefaultDnsRelayTimeout)
	defer cancel()
	inData := readBuff.Bytes()
	writeBuff := readBuff
	writeBuff.Resize(writeBuff.Start(), 0)
	if len(writeBuff.FreeBytes()) < resolver.SafeDnsPacketSize { // only create a new buffer when space don't enough
		writeBuff = rwOptions.NewPacketBuffer()
	}
	msg, err := resolver.RelayDnsPacket(ctx, inData, writeBuff.FreeBytes())
	if writeBuff != readBuff {
		readBuff.Release()
	}
	if err != nil {
		writeBuff.Release()
		return
	}
	writeBuff.Truncate(len(msg))
	if mutex != nil {
		mutex.Lock()
		defer mutex.Unlock()
	}
	conn := *writer
	if conn == nil {
		writeBuff.Release()
		return
	}
	err = conn.WritePacket(writeBuff, dest) // WritePacket will release writeBuff
	if err != nil {
		writeBuff.Release()
		return
	}
}

func (h *ListenerHandler) TypeMutation(typ C.Type) *ListenerHandler {
	handle := *h
	handle.ListenerHandler = h.ListenerHandler.TypeMutation(typ)
	return &handle
}
