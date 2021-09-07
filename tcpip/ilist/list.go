// 包 ilist 提供了侵入式链表的实现
package ilist

type Linker interface {
	Next() Element
	Prev() Element
	SetNext(Element)
	SetPrev(Element)
}

type Element interface {
	Linker
}

// ElementMapper 默认提供身份映射。
// 如果它们不相同，则可以替换它以提供将元素映射到链接器对象的结构。
// 在以下情况下通常不需要 ElementMapper：Linker 保持原样，Element 保持原样，
// 或者 Linker 和 Element 是相同类型
type ElementMapper struct{}

// linkerFor maps an Element to a Linker.
// This default implementation should be inline 1d
func (ElementMapper) linkerFor(elem Element) Linker {
	return elem
}

type List struct {
	head Element
	tail Element
}

func (l *List) Reset() {
	l.head = nil
	l.tail = nil
}

func (l *List) Empty() bool {
	return l.head == nil
}

func (l *List) Front() Element {
	return l.head
}

func (l *List) Back() Element {
	return l.tail
}

func (l *List) PushFront(e Element) {
	ElementMapper{}.linkerFor(e).SetPrev(nil)
	ElementMapper{}.linkerFor(e).SetNext(l.head) //当前头部作为新头部的下一个节点

	if l.head != nil {
		ElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}
	l.head = e
}

func (l *List) PushBack(e Element) {
	ElementMapper{}.linkerFor(e).SetPrev(l.tail) // 当前尾部作为新尾部的上一个节点
	ElementMapper{}.linkerFor(e).SetNext(nil)

	if l.tail != nil {
		ElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}
	l.tail = e
}

// 将m尾插到l,然后清除m
func (l *List) PushBackList(m *List) {
	// 如果没有
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else {
		ElementMapper{}.linkerFor(l.tail).SetNext(m.head)
		ElementMapper{}.linkerFor(m.head).SetPrev(l.tail)
		l.tail = m.tail
	}
	m.head = nil
	m.tail = nil
}

func (l *List) InsertAfter(b, e Element) {
	a := ElementMapper{}.linkerFor(b).Next()
	ElementMapper{}.linkerFor(e).SetNext(a)
	ElementMapper{}.linkerFor(e).SetPrev(b)
	ElementMapper{}.linkerFor(b).SetNext(e)

	if a != nil {
		ElementMapper{}.linkerFor(a).SetPrev(e)
	} else {
		l.tail = e
	}
}

func (l *List) InsertBefore(a, e Element) {
	b := ElementMapper{}.linkerFor(a).Prev()
	ElementMapper{}.linkerFor(e).SetPrev(b)
	ElementMapper{}.linkerFor(e).SetNext(a)
	ElementMapper{}.linkerFor(a).SetPrev(e)

	if b != nil {
		ElementMapper{}.linkerFor(b).SetNext(e)
	} else {
		l.head = e
	}
}

func (l *List) Remove(e Element) {
	prev := ElementMapper{}.linkerFor(e).Prev()
	next := ElementMapper{}.linkerFor(e).Next()

	if prev != nil {
		ElementMapper{}.linkerFor(prev).SetNext(next)
	} else {
		l.tail = next
	}

	if next != nil {
		ElementMapper{}.linkerFor(next).SetPrev(prev)
	} else {
		l.tail = prev
	}
}

type Entry struct {
	next Element
	prev Element
}

func (e *Entry) Next() Element {
	return e.next
}

func (e *Entry) Prev() Element {
	return e.prev
}

func (e *Entry) SetNext(elem Element) {
	e.next = elem
}

func (e *Entry) SetPrev(elem Element) {
	e.prev = elem
}
