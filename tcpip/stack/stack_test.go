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
	defaultMTU = 65536
)

type fakeNetworkProtocol struct {
}

func (f *fakeNetworkProtocol) Number() tcpip.NetworkProtocolNumber {
	return 114514
}

func init() {
	stack.RegisterNetworkProtocolFactory("fakeNet", func() stack.NetworkProtocol {
		return &fakeNetworkProtocol{}
	})
}

func TestStackBase(t *testing.T) {

	myStack := stack.New([]string{"fakeNet"})
	id, ep := channel.New(10, defaultMTU, "") // 这是一个物理设备
	log.Println(id)

	if err := myStack.CreateNIC(1, id); err != nil { // 将上面的物理设备抽象成我们的网卡对象
		panic(err)
	}
	myStack.AddAddress(1, 114514, "\x01") // 给网卡对象绑定一个IP地址 可以绑定多个

	buf := buffer.NewView(30)
	for i := range buf {
		buf[i] = 1
	}
	ep.Inject(114514, buf.ToVectoriseView())
}
