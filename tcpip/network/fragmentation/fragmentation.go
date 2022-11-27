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

type Fragmentation struct {
	mu           sync.Mutex
	highLimit    int
	lowLimit     int
	reassemblers map[uint32]*reassembler
	rList        reassemblerList
	size         int
	timeout      time.Duration
}

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

func (f *Fragmentation) Process(id uint32, first, last uint16, more bool, vv buffer.VectorisedView) (buffer.VectorisedView, bool) {
	log.Println("分片机制工作中", id, first, last, vv.First())
	f.mu.Lock()
	r, ok := f.reassemblers[id]
	if ok && r.tooOld(f.timeout) {
		// This is very likely to be an id-collision or someone performing a slow-rate attack.
		//f.release(r)
		ok = false
	}
	if !ok {
		r = newReassembler(id)
		f.reassemblers[id] = r
		f.rList.PushFront(r)
	}
	f.mu.Unlock()
	return buffer.VectorisedView{}, false
}
