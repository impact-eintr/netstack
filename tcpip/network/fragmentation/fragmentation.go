package fragmentation

import (
	"log"
	"netstack/tcpip/buffer"
	"sync"
	"time"
)

// DefaultReassembleTimeout is based on the linux stack: net.ipv4.ipfrag_time.
const DefaultReassembleTimeout = 30 * time.Second

// HighFragThreshold is the threshold at which we start trimming old
// fragmented packets. Linux uses a default value of 4 MB. See
// net.ipv4.ipfrag_high_thresh for more information.
const HighFragThreshold = 4 << 20 // 4MB

// LowFragThreshold is the threshold we reach to when we start dropping
// older fragmented packets. It's important that we keep enough room for newer
// packets to be re-assembled. Hence, this needs to be lower than
// HighFragThreshold enough. Linux uses a default value of 3 MB. See
// net.ipv4.ipfrag_low_thresh for more information.
const LowFragThreshold = 3 << 20 // 3MB

// Fragmentation 分片处理器对象
type Fragmentation struct {
	mu           sync.Mutex
	highLimit    int
	lowLimit     int
	reassemblers map[uint32]*reassembler // IP报文hash:重组器
	rList        reassemblerList
	size         int
	timeout      time.Duration
}

// NewFragmentation 新建一个分片处理器
func NewFragmentation(highMemoryLimit, lowMemoryLimit int, reassemblingTimeout time.Duration) *Fragmentation {
	if lowMemoryLimit >= highMemoryLimit {
		lowMemoryLimit = highMemoryLimit
	}

	if lowMemoryLimit < 0 {
		lowMemoryLimit = 0
	}

	return &Fragmentation{
		reassemblers: make(map[uint32]*reassembler),
		highLimit:    highMemoryLimit,
		lowLimit:     lowMemoryLimit,
		timeout:      reassemblingTimeout,
	}
}

// Process 处理ip报文分片
func (f *Fragmentation) Process(id uint32, first, last uint16, more bool, vv buffer.VectorisedView) (buffer.VectorisedView, bool) {
	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) { // 检测一个分片是否存在超过了30s
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		f.release(r)
		ok = false
	}
	if !ok { // 首次注册该报文的分片
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()

	res, done, consumed := r.process(first, last, more, vv)

	f.mu.Lock()
	f.size += consumed
	log.Printf("[%d]的分片 [%d,%d] 合并中\n", id, first, last)
	if done {
		f.release(r)
	}
	// Evict reassemblers if we are consuming more memory than highLimit until
	// we reach lowLimit.
	if f.size > f.highLimit {
		tail := f.rList.Back()
		for f.size > f.lowLimit && tail != nil {
			f.release(tail)
			tail = tail.Prev()
		}
	}
	f.mu.Unlock()
	return res, done
}

func (f *Fragmentation) release(r *reassembler) {
	// Before releasing a fragment we need to check if r is already marked as done.
	// Otherwise, we would delete it twice.
	if r.checkDoneOrMark() {
		return
	}

	delete(f.reassemblers, r.id)
	f.rList.Remove(r)
	f.size -= r.size
	if f.size < 0 {
		log.Printf("memory counter < 0 (%d), this is an accounting bug that requires investigation", f.size)
		f.size = 0
	}
}
