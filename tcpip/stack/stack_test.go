package stack_test

import (
	"netstack/tcpip/link/channel"
	"netstack/tcpip/stack"
	"testing"
)

const (
	defaultMTU = 65536
)

func TestStackBase(t *testing.T) {

	myStack := &stack.Stack{}
	id, _ := channel.New(10, defaultMTU, "")

	if err := myStack.CreateNIC(1, id); err != nil {
		panic(err)
	}
}
