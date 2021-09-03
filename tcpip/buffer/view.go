package buffer

type View []byte

func NewView(size int) View {
	return make(View, size)
}

func NewViewFromBytes(b []byte) View {
	return append(View(nil), b...)
}

func (v *View) TrimFront(count int) {
	*v = (*v)[count:]
}

func (v *View) CapLength(length int) {
	*v = (*v)[:length:length]
}

func (v View) ToVectorisedView() VectorisedView {
	return NewVectorisedView(len(v), []View{v})
}

// VectorisedView 是使用非连续内存的矢量化视图版本。它支持视图支持的所有便捷方法。
type VectorisedView struct {
	views []View
	size  int
}

func NewVectorisedView(size int, views []View) VectorisedView {
	return VectorisedView{views: views, size: size}
}

func (vv *VectorisedView) TrimFront(count int) {
	for count > 0 && len(vv.views) > 0 {
		if count < len(vv.views[0]) {
			vv.size -= count
			vv.views[0].TrimFront(count)
			return
		}
		count -= len(vv.views[0])
		vv.RemoveFirst()
	}
}

func (vv *VectorisedView) CapLength(length int) {
	if length < 0 {
		length = 0
	}
	if vv.size < length {
		return
	}
	vv.size = length
	for i := range vv.views {
		v := &vv.views[i]
		if len(*v) >= length {
			if length == 0 {
				vv.views = vv.views[:i]
			} else {
				v.CapLength(length)
				vv.views = vv.views[:i+1] // 更新view 这个写法太艹了 底层数组没有共享可以直接修改
			}
			return
		}
		length -= len(*v)
	}
}

// 会把buffer原来的内容覆盖
func (vv *VectorisedView) Clone(buffer []View) VectorisedView {
	return VectorisedView{views: append(buffer[:0], vv.views...), size: vv.size}
}

func (vv *VectorisedView) First() View {
	if len(vv.views) == 0 {
		return nil
	}
	return vv.views[0]
}

func (vv *VectorisedView) RemoveFirst() {
	if len(vv.views) == 0 {
		return
	}
	vv.size -= len(vv.views[0])
	vv.views = vv.views[1:]
}

func (vv *VectorisedView) Size() int {
	return vv.size
}

func (vv VectorisedView) ToView() View {
	u := make([]byte, 0, vv.size)
	for _, v := range vv.views {
		u = append(u, v...)
	}
	return u
}

func (vv VectorisedView) Views() []View {
	return vv.views
}
