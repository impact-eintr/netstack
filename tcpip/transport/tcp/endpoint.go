package tcp

// endpoint 表示TCP端点。该结构用作端点用户和协议实现之间的接口;让并发goroutine调用端点是合法的，
// 它们是正确同步的。然而，协议实现在单个goroutine中运行。
type endpoint struct {
}
