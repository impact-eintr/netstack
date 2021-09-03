package buffer

type Prependable struct {
	buf     View // Buf 是支持前置缓冲区的缓冲区
	usedIdx int  // 是缓冲区的使用部分开始的索引
}

func NewPrependable(size int) Prependable {
	return Prependable{}
}
