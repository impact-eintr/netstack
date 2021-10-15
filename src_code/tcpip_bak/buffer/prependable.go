package buffer

type Prependable struct {
	buf     View // Buf 是支持前置缓冲区的缓冲区
	usedIdx int  // 是缓冲区的使用部分开始的索引
}

func NewPrependable(size int) Prependable {
	return Prependable{}
}

func NewPrependableFromView(v View) Prependable {
	return Prependable{buf: v, usedIdx: 0}
}

func (p Prependable) View() View {
	return p.buf[p.usedIdx:]
}

func (p Prependable) UsedLength() inty {
	return len(p.buf) - p.usedIdx
}

func (p *Prependable) Prepend(size int) []byte {
	if size > p.usedIdx {
		return nil
	}

	p.usedIdx -= size
	return p.View()[:size:size]
}
