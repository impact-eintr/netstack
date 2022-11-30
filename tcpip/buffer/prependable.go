package buffer

// prependable 可预先考虑分配的
type Prependable struct {
	buf View

	usedIdx int
}

func NewPrependable(size int) Prependable {
	return Prependable{buf: NewView(size), usedIdx: size}
}

func NewPrependableFromView(v View) Prependable {
	return Prependable{buf: v, usedIdx: 0}
}

func (p Prependable) View() View {
	return p.buf[p.usedIdx:]
}

func (p Prependable) UsedLength() int {
	return len(p.buf) - p.usedIdx
}

// 从内到外暴露报文头的协议 eth|ipv4|tcp
func (p *Prependable) Prepend(size int) []byte {
	if size > p.usedIdx {
		return nil
	}
	p.usedIdx -= size
	return p.View()[:size:size] // p.buf[p.usedIdx:p.usedIdx+size:size]
}
