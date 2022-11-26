package stack_test

import (
	"log"
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"netstack/tcpip/link/channel"
	"netstack/tcpip/stack"
	"testing"
)

const (
	fakeNetHeaderLen = 12
	defaultMTU       = 65536
)

type fakeNetworkEndpoint struct {
	nicid      tcpip.NICID
	id         stack.NetworkEndpointID
	proto      *fakeNetworkProtocol
	dispatcher stack.TransportDispatcher
	linkEP     stack.LinkEndpoint
}

func (f *fakeNetworkEndpoint) DefaultTTL() uint8 {
	return 123
}

func (f *fakeNetworkEndpoint) MTU() uint32 {
	return f.linkEP.MTU() - uint32(f.MaxHeaderLength())
}

func (f *fakeNetworkEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return f.linkEP.Capabilities()
}

func (f *fakeNetworkEndpoint) MaxHeaderLength() uint16 {
	return f.linkEP.MaxHeaderLength() + fakeNetHeaderLen
}
func (f *fakeNetworkEndpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	b := hdr.Prepend(fakeNetHeaderLen)
	copy(b[:4], []byte(r.RemoteAddress))
	copy(b[4:8], []byte(f.id.LocalAddress))
	b[8] = byte(protocol)
	log.Println("写入网络层数据 下一层去往链路层", b, payload)

	return f.linkEP.WritePacket(r, hdr, payload, 114514)
}

func (f *fakeNetworkEndpoint) ID() *stack.NetworkEndpointID {
	return &f.id
}

func (f *fakeNetworkEndpoint) NICID() tcpip.NICID {
	return f.nicid
}

func (f *fakeNetworkEndpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
	log.Println("执行这个函数 接下来它会去向传输层分发数据")
}

func (f *fakeNetworkEndpoint) Close() {}

// dst|src|payload
type fakeNetworkProtocol struct{}

func (f *fakeNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return 114514
}

func (f *fakeNetworkProtocol) NewEndpoint(nicid tcpip.NICID, addr tcpip.Address, linkAddrCache stack.LinkAddressCache,
	dispatcher stack.TransportDispatcher, linkEP stack.LinkEndpoint) (stack.NetworkEndpoint, *tcpip.Error) {
	return &fakeNetworkEndpoint{
		nicid:      nicid,
		id:         stack.NetworkEndpointID{addr},
		proto:      f,
		dispatcher: dispatcher,
		linkEP:     linkEP,
	}, nil
}

func (f *fakeNetworkProtocol) MinimumPacketSize() int {
	return fakeNetHeaderLen
}

func (f *fakeNetworkProtocol) ParseAddresses(v buffer.View) (src, dst tcpip.Address) {
	return tcpip.Address(v[4:8]), tcpip.Address(v[0:4])
}

func (f *fakeNetworkProtocol) SetOption(option interface{}) *tcpip.Error {
	return nil
}

func (f *fakeNetworkProtocol) Option(option interface{}) *tcpip.Error {
	return nil
}

func init() {
	stack.RegisterNetworkProtocolFactory("fakeNet", func() stack.NetworkProtocol {
		return &fakeNetworkProtocol{}
	})
}

func TestStackBase(t *testing.T) {

	myStack := stack.New([]string{"fakeNet"}, nil, stack.Options{})
	id1, ep1 := channel.New(10, defaultMTU, "00:15:5d:26:d7:a1") // 这是一个物理设备

	if err := myStack.CreateNIC(1, id1); err != nil { // 将上面的物理设备抽象成我们的网卡对象
		panic(err)
	}
	myStack.AddAddress(1, 114514, "\x0a\xff\x01\x01") // 给网卡对象绑定一个IP地址 可以绑定多个

	id2, _ := channel.New(10, defaultMTU, "50:5B:C2:D0:96:57") // 这是一个物理设备
	if err := myStack.CreateNIC(2, id2); err != nil {          // 将上面的物理设备抽象成我们的网卡对象
		panic(err)
	}
	myStack.AddAddress(2, 114514, "\x0a\xff\x01\x02") // 给网卡对象绑定一个IP地址 可以绑定多个

	buf := buffer.NewView(30)
	for i := range buf {
		buf[i] = 0
	}
	// dst 10.255.1.2
	buf[0] = '\x0a'
	buf[1] = '\xff'
	buf[2] = '\x01'
	buf[3] = '\x02'
	// src 10.255.1.1
	buf[4] = '\x0a'
	buf[5] = '\xff'
	buf[6] = '\x01'
	buf[7] = '\x01'

	myStack.SetRouteTable([]tcpip.Route{
		{"\x01", "\x01", "\x00", 1},
		{"\x00", "\x01", "\x00", 2},
	})

	sendTo(t, myStack, tcpip.Address("\x0a\xff\x01\x02"))

	//log.Println(ep1.Drain())
	p := <-ep1.C
	log.Println(p)
}

func sendTo(t *testing.T, s *stack.Stack, addr tcpip.Address) {
	r, err := s.FindRoute(0, "", addr, 114514)
	if err != nil {
		t.Fatalf("FindRoute failed: %v", err)
	}
	defer r.Release()

	hdr := buffer.NewPrependable(int(r.MaxHeaderLength()))
	if err := r.WritePacket(hdr, buffer.VectorisedView{}, 10086, 123); err != nil {
		t.Errorf("WritePacket failed: %v", err)
		return
	}
}
