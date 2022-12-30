package stack

import (
	"netstack/tcpip"
	"netstack/tcpip/buffer"
	"sync"
)

// 网络层协议号和传输层协议号的组合 当作分流器的key值
type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber
	transport tcpip.TransportProtocolNumber
}

type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint
}

// transportDemuxer 解复用战队传输端点的数据包
// 他执行两级解复用：首先基于网络层和传输协议 然后基于端点ID
// 在我们注册完各种网络层、传输层协议后，我们还需要一个分流器让各种数据准确地找到自己的处理端，不能让一个ipv4的tcp连接最终被一个ipv6的udp处理端解析。
// 那么对于任意一个传输层数据流，它应当唯一标识为 `网络层协议-传输层协议-目标IP-目标端口-本地IP-本地端口`的一个六元组
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}

// 新建一个分流器
func newTransportDemuxer(stack *Stack) *transportDemuxer {
	d := &transportDemuxer{protocol: make(map[protocolIDs]*transportEndpoints)}

	for netProto := range stack.networkProtocols {
		for tranProto := range stack.transportProtocols {
			d.protocol[protocolIDs{network: netProto, transport: tranProto}] = &transportEndpoints{
				endpoints: make(map[TransportEndpointID]TransportEndpoint),
			}
		}
	}
	return d
}

// registerEndpoint 向分发器注册给定端点，以便将与端点ID匹配的数据包传递给它
func (d *transportDemuxer) registerEndpoint(netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	for i, n := range netProtos {
		if err := d.singleRegisterEndpoint(n, protocol, id, ep); err != nil {
			d.unregisterEndpoint(netProtos[:i], protocol, id) // 把刚才注册的注销掉
			return err
		}
	}
	return nil
}

func (d *transportDemuxer) singleRegisterEndpoint(netProto tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint) *tcpip.Error {
	eps, ok := d.protocol[protocolIDs{netProto, protocol}] // IPv4:udp
	if !ok {                                               // 未曾注册过这个传输端集合
		return nil
	}

	eps.mu.Lock()
	defer eps.mu.Unlock()

	if _, ok := eps.endpoints[id]; ok { // 遍历传输端集合
		return tcpip.ErrPortInUse
	}
	eps.endpoints[id] = ep
	return nil
}

// unregisterEndpoint 使用给定的id注销端点，使其不再接收任何数据包
func (d *transportDemuxer) unregisterEndpoint(netProtos []tcpip.NetworkProtocolNumber,
	protocol tcpip.TransportProtocolNumber, id TransportEndpointID) {
	for _, n := range netProtos {
		if eps, ok := d.protocol[protocolIDs{n, protocol}]; ok {
			eps.mu.Lock()
			delete(eps.endpoints, id)
			eps.mu.Unlock()
		}
	}
}

// 根据传输层的id来找到对应的传输端，再将数据包交给这个传输端处理
func (d *transportDemuxer) deliverPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView, id TransportEndpointID) bool {
	// 先看看分流器里有没有注册相关协议端，如果没有则返回false
	eps, ok := d.protocol[protocolIDs{r.NetProto, protocol}]
	if !ok {
		return false
	}
	// 从 eps 中找符合 id 的传输端
	eps.mu.RLock()
	ep := d.findEndpointLocked(eps, vv, id)
	eps.mu.RUnlock()

	if ep == nil {
		return false
	}

	// Deliver the packet
	ep.HandlePacket(r, id, vv)

	return true
}

func (d *transportDemuxer) deliverControlPacket(net tcpip.NetworkProtocolNumber,
	trans tcpip.TransportProtocolNumber, typ ControlType, extra uint32, vv buffer.VectorisedView, id TransportEndpointID) bool {
	return false
}

// 根据传输层id来找到相应的传输层端
// 当本地没有存在连接的时候 只有 LocalAddr:LocalPort 监听的传输端 也就是客户端来建立新连接
// 当本地存在连接的时候 就有可能找到 LAddr:LPort+RAddr:RPort 的传输端
func (d *transportDemuxer) findEndpointLocked(eps *transportEndpoints,
	vv buffer.VectorisedView, id TransportEndpointID) TransportEndpoint {
	if ep := eps.endpoints[id]; ep != nil { // IPv4:udp
		return ep
	}
	// Try to find a match with the id minus the local address.
	nid := id
	// 如果上面的 endpoints 没有找到，那么去掉本地ip地址，看看有没有相应的传输层端
	// 因为有时候传输层监听的时候没有绑定本地ip，也就是 any address，此时的 LocalAddress
	// 为空。
	nid.LocalAddress = ""
	if ep := eps.endpoints[nid]; ep != nil {
		return ep
	}

	// Try to find a match with the id minus the remote part.
	nid.LocalAddress = id.LocalAddress
	nid.RemoteAddress = ""
	nid.RemotePort = 0
	if ep := eps.endpoints[nid]; ep != nil {
		return ep
	}

	// Try to find a match with only the local port.
	nid.LocalAddress = ""
	return eps.endpoints[nid]
}
