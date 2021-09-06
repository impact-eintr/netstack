package stack

import (
	"sync"
	"time"

	"github.com/impact-eintr/netstack/tcpip"
)

const linkAddrCacheSize = 512 // 最大缓存条目

// 是一个固定大小的缓存，将 IP 地址映射到链接地址
// 条目存储在环形缓冲区中，最旧的条目首先被替换。
// 这个结构体对于并发使用是安全的
type linkAddrCache struct {
	// 缓存条目的有效期
	ageLimit time.Duration
	// 等待链接请求解析地址的时间
	resolutionTimeout time.Duration
	// 地址在失败前尝试解析的次数
	resolutionAttempts int

	mu      sync.Mutex
	cache   map[tcpip.FullAddress]*linkAddrEntry
	next    int // 下一个可用条目的数组索引
	entries [linkAddrCacheSize]linkAddrEntry
}

// linkAddrCache 中的一个条目
type linkAddrEntry struct {
	addr       tcpip.FullAddress
	linkAddr   tcpip.LinkAddress
	expiration time.Time
	s          entryState
}

// entryState 控制缓存中单个条目的状态
type entryState int

const (
	incomplete entryState = iota
	ready
	failed
	expired // 失效的
)
