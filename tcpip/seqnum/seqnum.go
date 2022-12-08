package seqnum

// Value represents the value of a sequence number.
type Value uint32

// Size represents the size (length) of a sequence number window
type Size uint32

// LessThan v < w
func (v Value) LessThan(w Value) bool {
	return int32(v-w) < 0
}

// LessThanEq returns true if v==w or v is before i.e., v < w.
func (v Value) LessThanEq(w Value) bool {
	if v == w {
		return true
	}
	return v.LessThan(w)
}

// InRange v ∈ [a, b)
func (v Value) InRange(a, b Value) bool {
	//return a <= v && v < b
	return v-a < b-a
}

// InWindows check v in [first, first+size)
func (v Value) InWindows(first Value, size Size) bool {
	return v.InRange(first, first.Add(size))
}

// Add return v + s
func (v Value) Add(s Size) Value {
	return v + Value(s)
}

// Size return the size of [v, w)
func (v Value) Size(w Value) Size {
	return Size(w - v)
}

// UpdateForward update the value to v+s
func (v *Value) UpdateForward(s Size) {
	*v += Value(s)
}

// Overlap checks if the window [a,a+b) overlaps with the window [x, x+y).
func Overlap(a Value, b Size, x Value, y Size) bool {
	return a.LessThan(x.Add(y)) && x.LessThan(a.Add(b))
}
