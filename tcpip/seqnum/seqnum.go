// 包 seqnum 定义了 TCP 序列号的类型和方法，以便它们适合 32 位字并在发生溢出时正常工作
package seqnum

// 一个序列号的值
type Value uint32

// size表示一个序号窗口的大小（长度）
type Size uint32
