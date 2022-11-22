package stack

import (
)

// 贯穿整个协议栈的路由，也就是在链路层和网络层都可以路由
// 如果目标地址是链路层地址，那么在链路层路由，
// 如果目标地址是网络层地址，那么在网络层路由。
type Route struct {
	// TODO
}
