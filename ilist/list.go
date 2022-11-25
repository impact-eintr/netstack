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

type ElementMapper struct{}

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
	ElementMapper{}.linkerFor(e).SetNext(l.head)
	ElementMapper{}.linkerFor(e).SetPrev(nil)

	if l.head != nil {
		ElementMapper{}.linkerFor(l.head).SetPrev(e)
	} else {
		l.tail = e
	}
	l.head = e
}

func (l *List) PushBack(e Element) {
	ElementMapper{}.linkerFor(e).SetNext(nil)
	ElementMapper{}.linkerFor(e).SetPrev(l.tail)

	if l.tail != nil {
		ElementMapper{}.linkerFor(l.tail).SetNext(e)
	} else {
		l.head = e
	}
	l.tail = e
}

// list merge
func (l *List) PushBackList(m *List) {
	if l.head == nil {
		l.head = m.head
		l.tail = m.tail
	} else if m.head != nil {
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
	ElementMapper{}.linkerFor(e).SetNext(a)
	ElementMapper{}.linkerFor(e).SetPrev(b)
	ElementMapper{}.linkerFor(a).SetPrev(e)
	if a != nil {
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
		l.head = next
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
