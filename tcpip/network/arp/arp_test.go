package arp_test

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/header"
	"netstack/tcpip/link/channel"
	"netstack/tcpip/network/arp"
	"netstack/tcpip/network/ipv4"
	"netstack/tcpip/stack"
	"testing"
	"time"
)

const (
	stackLinkAddr = tcpip.LinkAddress("\x0a\x0a\x0b\x0b\x0c\x0c") // 0a:0a:0b:0b:0c:0c
	stackAddr1    = tcpip.Address("\x0a\x00\x00\x01")             // 10.0.0.1
	stackAddr2    = tcpip.Address("\x0a\x00\x00\x02")             // 10.0.0.2
	stackAddrBad  = tcpip.Address("\x0a\x00\x00\x03")             // 10.0.0.3
)

type testContext struct {
	t      *testing.T
	linkEP *channel.Endpoint
	s      *stack.Stack
}

func newTestContext(t *testing.T) *testContext {
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName}, nil, stack.Options{})

	const defaultMTU = 65536
	id, linkEP := channel.New(256, defaultMTU, stackLinkAddr)
	if err := s.CreateNIC(1, id); err != nil {
		t.Fatalf("CreateNIC failed: %v", err)
	}

	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr1); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, ipv4.ProtocolNumber, stackAddr2); err != nil {
		t.Fatalf("AddAddress for ipv4 failed: %v", err)
	}
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		t.Fatalf("AddAddress for arp failed: %v", err)
	}

	s.SetRouteTable([]tcpip.Route{{
		Destination: "\x00\x00\x00\x00",
		Mask:        "\x00\x00\x00\x00",
		Gateway:     "",
		NIC:         1,
	}})

	return &testContext{
		t:      t,
		s:      s,
		linkEP: linkEP,
	}
}

func (c *testContext) cleanup() {
	close(c.linkEP.C)
}

func TestArpBase(t *testing.T) {
	c := newTestContext(t)
	defer c.cleanup()

	const senderMAC = "\x01\x02\x03\x04\x05\x06"
	const senderIPv4 = "\x0a\x00\x00\x02"

	v := make(buffer.View, header.ARPSize)
	h := header.ARP(v)
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)                  // 一个ARP请求
	copy(h.HardwareAddressSender(), senderMAC)  // Local MAC
	copy(h.ProtocolAddressSender(), senderIPv4) // Local IP

	inject := func(addr tcpip.Address) {
		copy(h.ProtocolAddressTarget(), addr)
		c.linkEP.Inject(arp.ProtocolNumber, v.ToVectorisedView()) // 往链路层注入一个arp报文 链路层将会自动分发它
	}

	inject(stackAddr1) // target IP  10.0.0.1
	select {
	case pkt := <-c.linkEP.C:
		if pkt.Proto != arp.ProtocolNumber {
			t.Fatalf("stackAddr1: expected ARP response, got network protocol number %v", pkt.Proto)
		}
		rep := header.ARP(pkt.Header)
		if !rep.IsValid() {
			t.Fatalf("stackAddr1: invalid ARP response len(pkt.Header)=%d", len(pkt.Header))
		}
		if tcpip.Address(rep.ProtocolAddressSender()) != stackAddr1 {
			t.Errorf("stackAddr1: expected sender to be set")
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
			t.Errorf("stackAddr1: expected sender to be stackLinkAddr, got %q", got)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Case #1 Time Out\n")
	}

	inject(stackAddr2)
	select {
	case pkt := <-c.linkEP.C:
		if pkt.Proto != arp.ProtocolNumber {
			t.Fatalf("stackAddr2: expected ARP response, got network protocol number %v", pkt.Proto)
		}
		rep := header.ARP(pkt.Header)
		if !rep.IsValid() {
			t.Fatalf("stackAddr2: invalid ARP response len(pkt.Header)=%d", len(pkt.Header))
		}
		if tcpip.Address(rep.ProtocolAddressSender()) != stackAddr2 {
			t.Errorf("stackAddr2: expected sender to be set")
		}
		if got := tcpip.LinkAddress(rep.HardwareAddressSender()); got != stackLinkAddr {
			t.Errorf("stackAddr2: expected sender to be stackLinkAddr, got %q", got)
		}

	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Case #2 Time Out\n")
	}

	inject(stackAddrBad)
	select {
	case pkt := <-c.linkEP.C:
		t.Errorf("stackAddrBad: unexpected packet sent, Proto=%v", pkt.Proto)
	case <-time.After(100 * time.Millisecond):
		// Sleep tests are gross, but this will only potentially flake
		// if there's a bug. If there is no bug this will reliably
		// succeed.
	}
}
