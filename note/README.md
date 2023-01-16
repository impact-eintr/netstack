# netstack

这是用于学习的笔记，内容包含很多来自互联网其他大佬的文章，代码主要来自谷歌的netstack项目，中文注释来自蓝桥课堂和自己的一些理解，可能有理解不到位或者错误的地方，欢迎指出。

首先我们要知道我们要干什么，我们要简单地手撕一个网络协议栈，什么是一个网络协议栈呢？

简单来说，就是操作系统内核用来处理截止传输层网络报文的逻辑，从链路到网络到传输层将来自网卡的比特流解析成用户进程可以理解的数据。

那么，有了这个认知，你可能会有种不太好的预感，是的，这是个巨大的工程。所幸谷歌为我们提供了一个极简版本的网络栈，在我跌跌撞撞地复现结束后，一个可以运行echo server的工程总共一万行出头，算是一个中等大小的项目了。

## 真实的内核如何接收网络包

1. 当网卡收到数据以后，以DMA的方式把网卡收到的帧写到内存里，再向CPU发起一个中断，以通知CPU有数据到达。
2. 当CPU收到中断请求后，会去调用网络设备驱动注册的中断处理函数。网卡的中断处理函数并不做过多工作，发出软中断请求，然后尽快释放CPU资源。
3. ksoftirqd内核线程检测到有软中断请求到达，调用poll开始轮询收包，受到后交给各级协议栈处理。对于tcp包来说，会被放到用户socker的接受队列中。

## 我们如何接受数据包

初始化协议栈

``` go

	// 新建相关协议的协议栈
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName},
		[]string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})
```


``` go

	s := &Stack{
		// 用来保存各种传输层协议
		transportProtocols: make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		// 用来保存各种网络层协议
		networkProtocols:   make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		// 用来保存各种地址解析协议
		linkAddrResolvers:  make(map[tcpip.NetworkProtocolNumber]LinkAddressResolver),
		// 用来保存所有使用该协议栈的网卡实例
		nics:               make(map[tcpip.NICID]*NIC),
		// 链路层MAC缓存器
		linkAddrCache:      newLinkAddrCache(ageLimit, resolutionTimeout, resolutionAttempts),
		// 端口管理器
		PortManager:        ports.NewPortManager(),
		// 协议栈时钟
		clock:              clock,
		// 协议栈状态管理器
		stats:              opts.Stats.FillIn(),
	}
```


先来给协议栈注册各种网络层协议

``` go

	// 添加指定的网络端协议 必须已经在init中注册过
	for _, name := range network {
		// 先检查这个网络协议是否注册过工厂方法
		netProtoFactory, ok := networkProtocols[name]
		if !ok {
			continue // 没有就略过
		}
		netProto := netProtoFactory()                    // 制造一个该型号协议的示实例
		s.networkProtocols[netProto.Number()] = netProto // 注册该型号的网络协议
		// 判断该协议是否支持链路层地址解析协议接口，如果支持添加到 s.linkAddrResolvers 中，
		// 如：ARP协议会添加 IPV4-ARP 的对应关系
		// 后面需要地址解析协议的时候会更改网络层协议号来找到相应的地址解析协议
		if r, ok := netProto.(LinkAddressResolver); ok {
			s.linkAddrResolvers[r.LinkAddressProtocol()] = r // 其实就是说： 声明arp支持地址解析
		}
	}

```

什么叫在init中注册过呢 以IP4为例

``` go
func init() {
	ids = make([]uint32, buckets)

	r := hash.RandN32(1 + buckets)
	for i := range ids {
		ids[i] = r[i] // 初始化ids
	}
	hashIV = r[buckets]

	stack.RegisterNetworkProtocolFactory(ProtocolName, func() stack.NetworkProtocol {
		return &protocol{}
	})
}

```

一旦导入了ipv4的包，就会执行init() stack包的RegisteerNetworkProtocol 将这个工厂方法保存到全局的networkProtolcols中

``` go

func RegisterNetworkProtocolFactory(name string, p NetworkProtocolFactory) {
	networkProtocols[name] = p
}
```

然后用这个协议工厂方法生成一个新的网络协议 并绑定到当前协议栈。为什么需要这个工厂方法呢？因为协议栈并不是唯一的，我们可以新建多个协议栈，然后绑定不同的协议。

在来注册各种传输层协议

``` go
    // 添加指定的传输层协议 必已经在init中注册过
	for _, name := range transport {
		transProtoFactory, ok := transportProtocols[name]
		if !ok {
			continue
		}
		transProto := transProtoFactory() // 新建一个传输层协议
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}
```

以udp为例 tcp太复杂了 之后单独说

``` go
func init() {
	stack.RegisterTransportProtocolFactory(ProtocolName, func() stack.TransportProtocol {
		return &protocol{}
	})
}
```

只要调用了udp/tcp的包，就会执行init()，用stack包的RegisterTransportProtocolFactory注册到全局的transportProtocols中

``` go
func RegisterTransportProtocolFactory(name string, p TransportProtocolFactory) {
	transportProtocols[name] = p
}
```

从全局的transportProtocols中找到目标传输层协议后，调用工厂方法，为当前协议栈注册一个传输层协议实例，随后我们就可以通过这个实例去创建udp/tcp连接了

- 分流器

``` go

	// NOTE 添加协议栈全局传输层分流器
	s.demux = newTransportDemuxer(s)
```

在我们注册完各种网络层、传输层协议后，我们还需要一个分流器让各种数据准确地找到自己的处理端，不能让一个ipv4的tcp连接最终被一个ipv6的udp处理端解析。

那么对于任意一个传输层数据流，它应当唯一标识为 `网络层协议-传输层协议-目标IP-目标端口-本地IP-本地端口`的一个六元组

我们用下面的结构来保存它

``` go
type transportDemuxer struct {
	protocol map[protocolIDs]*transportEndpoints
}

type protocolIDs struct {
	network   tcpip.NetworkProtocolNumber // 网络层协议
	transport tcpip.TransportProtocolNumber // 传输层协议
}

type transportEndpoints struct {
	mu        sync.RWMutex
	endpoints map[TransportEndpointID]TransportEndpoint // value是最终的处理端
}

type TransportEndpointID struct {
	LocalPort     uint16 // 本地端口
	LocalAddress  tcpip.Address // 本地IP
	RemotePort    uint16 // 目标端口
	RemoteAddress tcpip.Address // 目标IP
}
```


有了这个分流器，就可以很方便地找到一个传输层报文用哪个处理端解析了。

这样我们就初始化好了一个协议栈。

## 链路层设备

想要让两个不同主机上的用户进程通信，就需要网卡和网线来传递数据。

链路层设备其实就是网卡级别的设备，用于收发数据，这一层级使用以太网帧来包装数据

在我们的协议栈实现中，有两个东需要区分一下，一个是网卡，一个是网卡驱动。

``` go
// 网卡 提供基本的行为模式 具体的数据处理方式需要依赖网卡驱动
type NIC struct {
    // ...
}

// 负责底层网卡的io读写以及数据分发
// NOTE 也就是网卡驱动 提供具体的数据处理逻辑
type endpoint struct {
    // ...
}

```


这是一个基于linux tap网卡的网卡驱动

``` go
	linkID := fdbased.New(&fdbased.Options{
		FD:                 fd, // tap网卡的FD
		MTU:                1500, // 1500 以太网单个帧最大值
		Address:            tcpip.LinkAddress(maddr), // 抽象网卡的MAC
		ResolutionRequired: true, // 允许开启地址解析
		HandleLocal: true, // 允许本地环回
	})
```

在全局注册这个网卡驱动

``` go
func New(opts *Options) tcpip.LinkEndpointID {
	return stack.RegisterLinkEndpoint(e)
}
```


它有两个最主要的方法 一个用来写 一个用来读

``` go

// 将上层的报文经过链路层封装，写入网卡中，如果写入失败则丢弃该报文
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable,
	payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error 
    
// Attach 启动从文件描述符中读取数据包的goroutine,并通过提供的分发函数来分发数据报
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) 
```

那么如何为协议栈绑定一张网卡呢(相当于linux识别注册一张物理网卡，并加载其驱动程序)

``` go
// 新建抽象的网卡
	if err := s.CreateNamedNIC(1, "eth1", linkID); err != nil {
		log.Fatal(err)
	}
```

``` go
// 新建一个网卡对象，并且激活它 激活就是准备好从网卡中读取和写入数据
func (s *Stack) createNIC(id tcpip.NICID, name string, linkEP tcpip.LinkEndpointID, enable bool) *tcpip.Error {
	// 从全局寻找该链路层设备是否注册过
	ep := FindLinkEndpoint(linkEP)
	if ep == nil {
		return tcpip.ErrBadLinkEndpoint
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Make sure id is unique
	if _, ok := s.nics[id]; ok {
		return tcpip.ErrDuplicateNICID
	}
	// 新建网卡对象 包括 网卡归属的协议栈 网卡号 网卡名 网卡驱动
	n := newNIC(s, id, name, ep)

	// 给协议栈注册这个网卡设备
	s.nics[id] = n
	if enable {
		n.attachLinkEndpoint()
	}

	return nil
}
```

``` go
func (n *NIC) attachLinkEndpoint() {
	n.linkEP.Attach(n)
}
```

在上面的函数中，我们开启了网卡的数据读取机制，对于fdbased这个驱动而言，他的实现设这样的

``` go

// Attach 启动从文件描述符中读取数据包的goroutine,并通过提供的分发函数来分发数据报
func (e *endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.dispatcher = dispatcher  // 将这张网卡注册为该链路的网络分发器
	// 链接端点不可靠。保存传输端点后，它们将停止发送传出数据包，并拒绝所有传入数据包。
	go e.dispatchLoop()
}
    
// 循环地从fd中读取数据 然后将数据报分发给协议栈
func (e *endpoint) dispatchLoop() *tcpip.Error {
	for {
		cont, err := e.dispatch()
		if err != nil || !cont {
			if e.closed != nil {
				e.closed(err) // 阻塞中
			}
			return err
		}
	}
}
```


``` go
func (e *endpoint) dispatch() (bool, *tcpip.Error) {
	// 读取数据缓存的分配
	e.allocateViews(BufConfig)

	// 从网卡读取数据
	n, err := rawfile.BlockingReadv(e.fd, e.iovecs) // 读到ioves中相当于读到views中
	if err != nil {
		return false, err
	}
	if n <= e.hdrSize {
		return false, nil // 读到的数据比头部还小 直接丢弃
	}

	var (
		p                             tcpip.NetworkProtocolNumber
		remoteLinkAddr, localLinkAddr tcpip.LinkAddress // 目标MAC 源MAC
	)
	// 获取以太网头部信息
	eth := header.Ethernet(e.views[0])
	p = eth.Type()
	remoteLinkAddr = eth.SourceAddress()
	localLinkAddr = eth.DestinationAddress()

	used := e.capViews(n, BufConfig)                  // 从缓存中截有效的内容
	vv := buffer.NewVectorisedView(n, e.views[:used]) // 用这些有效的内容构建vv
	vv.TrimFront(e.hdrSize)                           // 将数据内容删除以太网头部信息 将网络层作为数据头

	switch p {
	case header.ARPProtocolNumber, header.IPv4ProtocolNumber:
		logger.GetInstance().Info(logger.ETH, func() {
			log.Println("链路层收到报文,来自: ", remoteLinkAddr, localLinkAddr)
		})
		e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, localLinkAddr, p, vv)
	case header.IPv6ProtocolNumber:
		e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, localLinkAddr, p, vv)
	default:
		log.Println("未知类型的非法报文")
	}

	// 将分发后的数据无效化(设置nil可以让gc回收这些内存)
	for i := 0; i < used; i++ {
		e.views[i] = nil
	}

	return true, nil
}
```

这样就成功激活了一张网卡


## IP 地址

有了网卡，我们还得给他绑定个IP地址。

``` go
    // 在该协议栈上添加和注册相应的网络层 1 就是刚才激活的网卡号
	if err := s.AddAddress(1, proto, addr); err != nil {
		log.Fatal(err)
	}
```


``` go

// 一路调用到这个函数
func (s *Stack) AddAddressWithOptions(...) {
    // 检查网卡是否存在
	nic := s.nics[id]
	if nic == nil {
		return tcpip.ErrUnknownNICID
	}

	return nic.AddAddressWithOptions(protocol, addr, peb)
}

	_, err := n.addAddressLocked(protocol, addr, peb, false)
    
    
```

给目标网卡绑定IP地址

``` go
func (n *NIC) addAddressLocked(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address,
	peb PrimaryEndpointBehavior, replace bool) (*referencedNetworkEndpoint, *tcpip.Error) {
	// 检查网卡绑定的协议栈是否注册过该网络协议
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		return nil, tcpip.ErrUnknownProtocol
	}

	// 比如netProto是ipv4 会调用ipv4.NewEndpoint 新建一个网络端
	ep, err := netProto.NewEndpoint(n.id, addr, n.stack, n, n.linkEP)
	if err != nil {
		return nil, err
	}

	// 获取网络层端的id 其实就是ip地址
	id := *ep.ID()
	if ref, ok := n.endpoints[id]; ok {
		// 不是替换 且该id已经存在
		if !replace {
			return nil, tcpip.ErrDuplicateAddress
		}
		n.removeEndpointLocked(ref) // 这里被调用的时候已经上过锁了 NOTE
	}

	// 新建一个网络端点的引用 为什么是一个引用
	// 这是为了复用 所有使用该IP地址的传输层报文都可以复用它
	ref := &referencedNetworkEndpoint{
		refs:           1, // 初始的引用计数
		ep:             ep, // 引用的网络端点
		nic:            n, // 网络端点所在的网卡
		protocol:       protocol, // 网络协议
		holdsInsertRef: true, // 防止空引用
	}

	// 如果该网卡驱动 配置了允许地址解析
	// 我们让网卡绑定的协议栈来作为该网络端点的MAC解析缓存器
	// 这样当我们向目标地址发送ip报文的时候 会检查缓存里是否存在 ip:mac 的对应关系
	// 如果不存在 就会调用arp协议发广播来定位这个ip对应的设备
	if n.linkEP.Capabilities()&CapabilityResolutionRequired != 0 {
		if _, ok := n.stack.linkAddrResolvers[protocol]; ok {
			ref.linkCache = n.stack
		}
	}

	// 注册该网络端
	n.endpoints[id] = ref

	logger.GetInstance().Info(logger.IP, func() {
		log.Printf("基于[%d]协议 为 #%d 网卡 添加网络层实现 并绑定地址到: %s\n", netProto.Number(), n.id, ep.ID().LocalAddress)
	})

	/*
	   [tcp]->192.168.1.1->192.168.1.2->172.10.1.1->...
	   [udp]->10.10.1.1->192.168.1.1->...
	  **/
	l, ok := n.primary[protocol]
	if !ok {
		l = &ilist.List{}
		n.primary[protocol] = l
	}

	// 保存该ip的引用
	switch peb {
	case CanBePrimaryEndpoint:
		l.PushBack(ref)
	case FirstPrimaryEndpoint:
		l.PushFront(ref)
	}
	return ref, nil
}
```

这样我们就给网卡成功绑了一个IP地址

需要注意一个地方，如果我们的网卡驱动配置了允许地址解析，我们就在需要地址解析的时候去检查本地 ip:mac缓存 没有的话 会发送arp广播报文来询问局域网

### 地址解析

两个问题

1. 什么时候需要地址解析
2. 缓存的设计与miss后查询

#### 什么时候地址解析

地址解析，其实就是目标地址解析，也就是说我们有目标的ip地址，但是没有对应的mac地址，所以这个问题发生在发送报文的时候

我们用tcp连接建立来举例，当然这里不设计tcp的细节。

在我们创建了一个tcp客户端并调用connect时，我们将会往服务端发送一个syn同步报文

``` go
func (e *endpoint) connect(...) {
    // ...
    // 根据目标ip查找路由信息
	r, err := e.stack.FindRoute(nicid, e.id.LocalAddress, addr.Addr, netProto)
	if err != nil {
		return err
	}
	defer r.Release()

    // 开启三次握手 写入报文 ...

}


```

这个`FindRoute`就是在写入syn报文前获取本机ip mac 和 目标ip 但依旧没有目标mac


``` go

// FindRoute 路由查找实现，比如当tcp建立连接时，会用该函数得到路由信息
// 注意仅仅包含 SrcMAC SrcIp DstIp 没有 DstMAC
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address,
	netProto tcpip.NetworkProtocolNumber) (Route, *tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for i := range s.routeTable {
		if (id != 0 && id != s.routeTable[i].NIC) || // 检查是否是对应的网卡
			(len(remoteAddr) != 0 && !s.routeTable[i].Match(remoteAddr)) {
			continue
		}

		nic := s.nics[s.routeTable[i].NIC] // 在协议栈里找到这张网卡
		if nic == nil {
			continue
		}

		var ref *referencedNetworkEndpoint
		if len(localAddr) != 0 { // 要是指定了本地ip
			ref = nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint) // 找到绑定LocalAddr的IP端
		} else { // 要是没指定本地ip 从当前网卡绑定的所有ip里找个能用的
			ref = nic.primaryEndpoint(netProto)
		}
		if ref == nil {
			continue
		}

		if len(remoteAddr) == 0 {
			// If no remote address was provided, then the route
			// provided will refer to the link local address.
			remoteAddr = ref.ep.ID().LocalAddress // 发回自己? TODO
		}

		// 构建一个路由 包括 目标ip 目标mac 本地ip 本地mac
		r := makeRoute(netProto, ref.ep.ID().LocalAddress, remoteAddr, nic.linkEP.LinkAddress(), ref)
		r.NextHop = s.routeTable[i].Gateway
		logger.GetInstance().Info(logger.IP, func() {
			log.Println(r.LocalLinkAddress, r.LocalAddress, r.RemoteLinkAddress, r.RemoteAddress, r.NextHop)
		})
		return r, nil
	}

	return Route{}, tcpip.ErrNoRoute
}
```


这部分的实现其实隐藏在三次握手的过程中


``` go
// 开启三次握手
func (h *handshake) execute() *tcpip.Error {
	// 是否需要拿到下一条地址
	if h.ep.route.IsResolutionRequired() {
		if err := h.resolveRoute(); err != nil {
			return err
		}
	}
    // ...
}
```


``` go
// 检查是否允许了地址解析 首先检查是否配置了mac缓存 然后检查目标mac是否已经存在
func (r *Route) IsResolutionRequired() bool {
	return r.ref.linkCache != nil && r.RemoteLinkAddress == ""
}
```

注意如果我们的链路层设备不支持地址解析，比如loopback设备，tcp将会把mubiaomac设置为本地mac，意为本地环回。

#### 缓存的设计

实际的地址解析逻辑在下面这段代码中

``` go
// Resolve 如有必要，解决尝试解析链接地址的问题。如果地址解析需要阻塞，则返回ErrWouldBlock，
// 例如等待ARP回复。地址解析完成（成功与否）时通知Waker。
// 如果需要地址解析，则返回ErrNoLinkAddress和通知通道，以阻止顶级调用者。
// 地址解析完成后，通道关闭（不管成功与否）。
func (r *Route) Resolve(waker *sleep.Waker) (<-chan struct{}, *tcpip.Error) {
	if !r.IsResolutionRequired() {
		return nil, nil
	}

	nextAddr := r.NextHop
	if nextAddr == "" {
		// Local link address is already known.
		if r.RemoteAddress == r.LocalAddress { // 发给自己
			r.RemoteLinkAddress = r.LocalLinkAddress // MAC 就是自己
			return nil, nil
		}
		nextAddr = r.RemoteAddress // 下一跳是远端机
	}

	// 调用地址解析协议来解析IP地址
	linkAddr, ch, err := r.ref.linkCache.GetLinkAddress(r.ref.nic.ID(), nextAddr, r.LocalAddress, r.NetProto, waker)
	if err != nil {
		return ch, err
	}
	r.RemoteLinkAddress = linkAddr
	return nil, nil
}
```


我们来看看这个地址解析的缓存设计

``` go
func (s *Stack) GetLinkAddress(nicid tcpip.NICID, addr, localAddr tcpip.Address,
	protocol tcpip.NetworkProtocolNumber, w *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	s.mu.RLock()
	// 获取网卡对象
	nic := s.nics[nicid]
	if nic == nil {
		s.mu.RUnlock()
		return "", nil, tcpip.ErrUnknownNICID
	}
	s.mu.RUnlock()

	fullAddr := tcpip.FullAddress{NIC: nicid, Addr: addr} // addr 可能是Remote IP Address
	// 根据网络层协议号找到对应的地址解析协议
	linkRes := s.linkAddrResolvers[protocol]
	return s.linkAddrCache.get(fullAddr, linkRes, localAddr, nic.linkEP, w)
}
```


``` go
// get reports any known link address for k.
func (c *linkAddrCache) get(k tcpip.FullAddress, linkRes LinkAddressResolver,
	localAddr tcpip.Address, linkEP LinkEndpoint, waker *sleep.Waker) (tcpip.LinkAddress, <-chan struct{}, *tcpip.Error) {
	logger.GetInstance().Info(logger.ETH, func() {
		log.Println("在arp本地缓存中寻找", k)
	})
	if linkRes != nil {
		if addr, ok := linkRes.ResolveStaticAddress(k.Addr); ok {
			return addr, nil, nil
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	// 尝试从缓存中得到MAC地址
	if entry, ok := c.cache[k]; ok {
		switch s := entry.state(); s {
		case expired: // 过期了
		case ready:
			return entry.linkAddr, nil, nil
		case failed:
			return "", nil, tcpip.ErrNoLinkAddress
		case incomplete:
			// Address resolution is still in progress.
			entry.addWaker(waker)
			return "", entry.done, tcpip.ErrWouldBlock
		default:
			panic(fmt.Sprintf("invalid cache entry state: %s", s))
		}
	}

	if linkRes == nil {
		return "", nil, tcpip.ErrNoLinkAddress
	}

	// Add 'incomplete' entry in the cache to mark that resolution is in progress.
	e := c.makeAndAddEntry(k, "")
	e.addWaker(waker)

	go c.startAddressResolution(k, linkRes, localAddr, linkEP, e.done)

	return "", e.done, tcpip.ErrWouldBlock
}
```
简单来说，一个LRU策略的缓存，如果失效了，就找arp协议发送广播报文。

``` go
// LinkAddressRequest implements stack.LinkAddressResolver.
func (*protocol) LinkAddressRequest(addr, localAddr tcpip.Address, linkEP stack.LinkEndpoint) *tcpip.Error {
	r := &stack.Route{
		RemoteLinkAddress: broadcastMAC,
	}

	hdr := buffer.NewPrependable(int(linkEP.MaxHeaderLength()) + header.ARPSize)
	h := header.ARP(hdr.Prepend(header.ARPSize))
	h.SetIPv4OverEthernet()
	h.SetOp(header.ARPRequest)
	copy(h.HardwareAddressSender(), linkEP.LinkAddress())
	copy(h.ProtocolAddressSender(), localAddr)
	copy(h.ProtocolAddressTarget(), addr)
	log.Println("arp发起广播 寻找:", addr, r)
	return linkEP.WritePacket(r, hdr, buffer.VectorisedView{}, ProtocolNumber)
}
```

绑定了目标ip的主机受到这个广播报文的时候，会回复一个报文，内容是自己的mac地址，同时更新自己的arp缓存。


## 网络层

解析过地址后，我们拥有了目标mac、目标ip，现在我们可以在网络层写数据了。

还是以tcp的三次握手为例，检验第一次发送syn同步报文。

``` go
// tcp三次握手流程
func (h *handshake) execute() *tcpip.Error {
    // 地址解析
    // ...
    
	// 如果是客户端发送 syn 报文，如果是服务端发送 syn+ack 报文
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
}


func sendSynTCP(r *stack.Route, ...) {
	err := sendTCP(r, id, buffer.VectorisedView{}, r.DefaultTTL(), flags, seq, ack, rcvWnd, options)
}

func sendTCP(r *stack.Route, ...) {
    // tcp报文编码
    
	return r.WritePacket(hdr, data, ProtocolNumber, ttl)
}
```

我们将调用Route.WritePacket来执行网路层的写入

``` go
func (r *Route) WritePacket(hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	// 路由对应的IP的WritePacket
	err := r.ref.ep.WritePacket(r, hdr, payload, protocol, ttl)
	if err == tcpip.ErrNoRoute {
		r.Stats().IP.OutgoingPacketErrors.Increment()
	}
	return err
}
```

我们这里查看最一般的IPV4的实现，这条路由将调用ipv4的WritePacket函数

``` go

// WritePacket writes a packet to the given destination address and protocol.
// 将传输层的数据封装加上IP头，并调用网卡的写入接口，写入IP报文
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable, payload buffer.VectorisedView,
	protocol tcpip.TransportProtocolNumber, ttl uint8) *tcpip.Error {
	// 预留ip报文的空间
	ip := header.IPv4(hdr.Prepend(header.IPv4MinimumSize))
	length := uint16(hdr.UsedLength() + payload.Size())
	id := uint32(0)
	// 如果报文长度大于68
	if length > header.IPv4MaximumHeaderSize+8 {
		// Packets of 68 bytes or less are required by RFC 791 to not be
		// fragmented, so we only assign ids to larger packets.
		id = atomic.AddUint32(&ids[hashRoute(r, protocol)%buckets], 1)
	}
	// ip首部编码
	ip.Encode(&header.IPv4Fields{
		IHL:         header.IPv4MinimumSize,
		TotalLength: length,
		ID:          uint16(id),
		TTL:         ttl,
		Protocol:    uint8(protocol),
		SrcAddr:     r.LocalAddress,
		DstAddr:     r.RemoteAddress,
	})
	// 计算校验和和设置校验和
	ip.SetChecksum(^ip.CalculateChecksum())
	r.Stats().IP.PacketsSent.Increment()

	// 写入网卡接口
	return e.linkEP.WritePacket(r, hdr, payload, ProtocolNumber)
}

```

在前面我们提到过链路层设备拥有读写两个接口，在激活设备的时候我们执行了读取函数，现在，我们该使用写入函数了(以fdbased为例)。

``` go
// 将上层的报文经过链路层封装，写入网卡中，如果写入失败则丢弃该报文
func (e *endpoint) WritePacket(r *stack.Route, hdr buffer.Prependable,
	payload buffer.VectorisedView, protocol tcpip.NetworkProtocolNumber) *tcpip.Error {
	// 如果目标地址是设备自己 那么将报文重新返回给协议栈 也就是环回
	if e.handleLocal && r.LocalAddress != "" && r.LocalAddress == r.RemoteAddress {
		views := make([]buffer.View, 1, 1+len(payload.Views()))
		views[0] = hdr.View()
		views = append(views, payload.Views()...)
		vv := buffer.NewVectorisedView(len(views[0])+payload.Size(), views) // 添加报文头
		e.dispatcher.DeliverNetworkPacket(e, r.RemoteLinkAddress, r.LocalLinkAddress,
			protocol, vv) // 分发数据报
		return nil
	}
	
	// 非本地环回数据
	// 封装增加以太网头部
	eth := header.Ethernet(hdr.Prepend(header.EthernetMinimumSize)) // 分配14B的内存
	ethHdr := &header.EthernetFields{                               // 配置以太帧信息
		DstAddr: r.RemoteLinkAddress,
		Type:    protocol,
	}
	// 如果路由信息中有配置源MAC地址，那么使用该地址
	// 如果没有，则使用本网卡的地址
	if r.LocalLinkAddress != "" {
		ethHdr.SrcAddr = r.LocalLinkAddress
	} else {
		ethHdr.SrcAddr = e.addr
	}
	eth.Encode(ethHdr) // 将以太帧信息作为报文头编入
	logger.GetInstance().Info(logger.ETH, func() {
		log.Println(ethHdr.SrcAddr, "链路层写回以太报文 ", r.RemoteLinkAddress, " to ", r.RemoteAddress)
	})
	// 写入网卡中
	if payload.Size() == 0 {
		return rawfile.NonBlockingWrite(e.fd, hdr.View())
	}
	return rawfile.NonBlockingWrite2(e.fd, hdr.View(), payload.ToView())
}

```

我们现在来捋一下，除了传输层以外的数据传输机制：

首先，数据发送方将数据从应用层复制数据到传输层，在封装传输层数据之前，我们会先解析路由。

路由: 网卡-网络协议-本地IP-本地MAC-目标IP-目标MAC

先查找路由表，查看路由表中是否有目标网卡，如果有，检查指定IP该网卡是否绑定过，如果没有指定IP,就从网卡绑定的IP里找一个能用的，然后本地MAC就使用这个网卡的MAC。目标IP是数据发送方提供的，目标MAC通过查询arp缓存或者发送arp广播获取。

有了路由信息，我们就可以执行网络层和链路层的工作了。从路由信息中获取IP的处理端点，封装IP报文，封装以太报文，写入网卡，网卡将这些数据发送出去。

目标主机网卡接受到数据时，dispatchLoop中的阻塞读不再阻塞，读取数据。解析以太报文，获取远端IP和远端MAC，在上面我们新建网卡的时候，我们已经将这张网卡作为本链路的网络分发器，所以调用网卡的分发函数。

``` go

	case header.ARPProtocolNumber, header.IPv4ProtocolNumber:
		e.dispatcher.DeliverNetworkPacket(e, remoteLinkAddr, localLinkAddr, p, vv)
```

``` go
// DeliverNetworkPacket 当 NIC 从物理接口接收数据包时，将调用函数 DeliverNetworkPacket，用来分发网络层数据包。
// 比如 protocol 是 arp 协议号，那么会找到arp.HandlePacket来处理数据报。
// 简单来说就是根据网络层协议和目的地址来找到相应的网络层端，将网络层数据发给它，
// 当前实现的网络层协议有 arp、ipv4 和 ipv6。
func (n *NIC) DeliverNetworkPacket(linkEP LinkEndpoint, remoteLinkAddr, localLinkAddr tcpip.LinkAddress,
	protocol tcpip.NetworkProtocolNumber, vv buffer.VectorisedView) {
	// 检查本协议栈是否注册过该网络协议
	netProto, ok := n.stack.networkProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}

	// 网络层协议状态统计
	if netProto.Number() == header.IPv4ProtocolNumber || netProto.Number() == header.IPv6ProtocolNumber {
		n.stack.stats.IP.PacketsReceived.Increment()
	}

	// 报文内容过小 判断为受损报文 丢弃
	if len(vv.First()) < netProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	// 解析源 IP 和目标IP
	src, dst := netProto.ParseAddresses(vv.First())
	// 根据网络协议和数据包的目的地址，找到绑定该目标地址的网络端
	if ref := n.getRef(protocol, dst); ref != nil {
		// 路由 源 与 目标 反转
		r := makeRoute(protocol, dst, src, linkEP.LinkAddress(), ref)
		r.RemoteLinkAddress = remoteLinkAddr
		// 将数据包分发给网络层
		ref.ep.HandlePacket(&r, vv)
		ref.decRef()
		return
	}

	// 如果配置了允许转发 什么意思呢
	// 就是说当前网卡并没有找到目标IP 我们来试试本机的其他网卡
	// 其他网卡-其他网卡上的一个可用地址-目标地址
	if n.stack.Forwarding() {
		r, err := n.stack.FindRoute(0, dst, src, protocol) // FIXME 将dst和src调转?
		if err != nil {
			n.stack.stats.IP.InvalidAddressesReceived.Increment()
			return
		}
		defer r.Release()

		r.LocalLinkAddress = n.linkEP.LinkAddress()
		r.RemoteLinkAddress = remoteLinkAddr

		// Found a NIC.
		n := r.ref.nic
		n.mu.RLock()
		ref, ok := n.endpoints[NetworkEndpointID{dst}] // 检查这张网卡是否绑定了目标IP
		n.mu.RUnlock()

		if ok && ref.tryIncRef() {
			ref.ep.HandlePacket(&r, vv)
			logger.NOTICE("转发数据")
			ref.decRef()
		} else {
			// n doesn't have a destination endpoint.
			// Send the packet out of n.
			hdr := buffer.NewPrependableFromView(vv.First())
			vv.RemoveFirst()
			n.linkEP.WritePacket(&r, hdr, vv, protocol)
		}
		return
	}

	n.stack.stats.IP.InvalidAddressesReceived.Increment()
}


```

转发模式我并不能确保理解正确。

可以看到，网卡找到对方要求处理的IP所绑定的网络端后，调用其HandlePacket 进行网络层数据的分发。

看一下IP报文如何处理:


``` go
// HandlePacket is called by the link layer when new ipv4 packets arrive for
// this endpoint.
// 收到ip包的处理
func (e *endpoint) HandlePacket(r *stack.Route, vv buffer.VectorisedView) {
	// 得到ip报文
	h := header.IPv4(vv.First())
	// 检查报文是否有效
	if !h.IsValid(vv.Size()) {
		return
	}
	logger.GetInstance().Info(logger.IP, func() {
		log.Println(h)
	})

	hlen := int(h.HeaderLength())
	tlen := int(h.TotalLength())
	vv.TrimFront(hlen)
	vv.CapLength(tlen - hlen)

	// 报文重组
	more := (h.Flags() & header.IPv4FlagMoreFragments) != 0
	// 是否需要ip重组
	if more || h.FragmentOffset() != 0 {
		// The packet is a fragment, let's try to reassemble it.
		last := h.FragmentOffset() + uint16(vv.Size()) - 1
		var ready bool
		// ip分片重组
		vv, ready = e.fragmentation.Process(hash.IPv4FragmentHash(h), h.FragmentOffset(), last, more, vv)
		if !ready {
			return
		}
	}

	// 得到传输层的协议
	p := h.TransportProtocol()
	// 如果时ICMP协议，则进入ICMP处理函数
	if p == header.ICMPv4ProtocolNumber {
		e.handleICMP(r, vv)
		return
	}
	r.Stats().IP.PacketsDelivered.Increment()
	// 根据协议分发到不同处理函数，比如协议时TCP，会进入tcp.HandlePacket
	logger.GetInstance().Info(logger.IP, func() {
		log.Printf("准备前往 UDP/TCP recv ipv4 packet %d bytes, proto: 0x%x", tlen, p)
	})
	e.dispatcher.DeliverTransportPacket(r, p, vv)
}
```

可以发现，IP报文有一个分片重组的机制，IP报文最大可以总长65535，但是以太网可承载布料这么多数据，所以需要分片发送，给同一IP报文的不同分片编号，接受者收到片段后缓存并进行堆排序，当所有分片均收到以后，将排好序的数据一次性分发给传输层。


``` go
// 缓存并排序
	if r.updateHoles(first, last, more) {
		// We store the incoming packet only if it filled some holes.
		heap.Push(&r.heap, fragment{offset: first, vv: vv.Clone(nil)})
		consumed = vv.Size()
		r.size += consumed
	}
	
// 全部收集后组合数据
	for h.Len() > 0 {
		curr := heap.Pop(h).(fragment)
		if int(curr.offset) < size {
			curr.vv.TrimFront(size - int(curr.offset)) // 截取重复的部分
		} else if int(curr.offset) > size {
			return buffer.VectorisedView{}, fmt.Errorf("packet has a hole, expected offset %d, got %d", size, curr.offset)
		}
		// curr.offset == size 没有空洞 紧密排布
		size += curr.vv.Size()
		views = append(views, curr.vv.Views()...)
	}
	return buffer.NewVectorisedView(size, views), nil
```

我们的连接在这一步需要进一步地分发，这仍将是网卡来实现的。

``` go
// DeliverTransportPacket delivers packets to the appropriate
// transport protocol endpoint.
func (n *NIC) DeliverTransportPacket(r *Route, protocol tcpip.TransportProtocolNumber, vv buffer.VectorisedView) {
	// 先查找协议栈是否注册了该传输层协议
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stack.stats.UnknownProtocolRcvdPackets.Increment()
		return
	}
	transProto := state.proto
	// 如果报文长度比该协议最小报文长度还小，那么丢弃它
	if len(vv.First()) < transProto.MinimumPacketSize() {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	// 解析报文得到源端口和目的端口
	srcPort, dstPort, err := transProto.ParsePorts(vv.First())
	if err != nil {
		n.stack.stats.MalformedRcvdPackets.Increment()
		return
	}
	id := TransportEndpointID{dstPort, r.LocalAddress, srcPort, r.RemoteAddress}
	// 调用分流器，根据传输层协议和传输层id分发数据报文
	// 现在本网卡中尝试分发
	if n.demux.deliverPacket(r, protocol, vv, id) {
		return
	}
	// 本网卡中没有目标六元组 在整个协议栈尝试分发
	if n.stack.demux.deliverPacket(r, protocol, vv, id) {
		return
	}
	// ...
}

```


``` go
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
	// listener 的情况 本地没有这个 dstIP+dstPort:srcIP+srcPort 的连接交由
	// ""+0:srcIP+srcPort的Listener来处理
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
```


这里需要解释一下，我们提到过对于任意一个传输层数据流，它应当唯一标识为 `网络层协议-传输层协议-目标IP-目标端口-本地IP-本地端口`的一个六元组，协议栈负责保存这个六元组。

这里会讲的比较乱，因为前面没有铺垫，所以我们需要了解tcp的一部分通信过程。

``` go
	// 首先我们需要绑定一个端口
	if err := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: addr, Port: uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	// 然后我们开始监听这个tcp端点
	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}
	
	// 使用Accept从listen的tcp端点中可以获取一个新的tcp端点
	conn, err := listener.Accept()
	if err != nil {
		log.Println(err)
	}
	log.Println("服务端 建立连接")
		
	// 我们使用这个新的tcp端点可以与客户端进行通信

```

在我们Listen之后，listener这个tcp端点就对应着处理所有 ""+0:srcIP+srcPort的情况，也就是一个客户端创建新连接，服务端没有任何此连接的信息(dstIP+dstPort:srcIP+srcPort)，所以就有了下面的逻辑：

``` go
func (e *endpoint) HandlePacket(r *stack.Route, id stack.TransportEndpointID, vv buffer.VectorisedView) {
	// ...
	if e.segmentQueue.enqueue(s) {
		// 对于 端口监听者 listener 而言这里唤醒的是 protocolListenLoop
		// 对于普通tcp连接 conn 而言这里唤醒的是 protocolMainLoop
		e.newSegmentWaker.Assert()
	}
}
```

这样我们就解析完了传输层以外的主机网络栈，并将传输层数据分发到了正确的端点。

那么传输层协议是如何实现的呢，首先，传输层是建立在上面的主机网络栈之上的，无需关注底层的细节。

#### 连接的建立

``` go
			c	   flag  	s
生成ISN1	|				|
   sync_sent|------sync---->|sync_rcvd
			|				|
			|				|生成ISN2
 established|<--sync|ack----|
			|				|
			|				|
			|------ack----->|established
```

一个经典的三次握手，我们使用一个handshake对象对其进行管理


``` go

// protocolMainLoop 是TCP协议的主循环。它在自己的goroutine中运行，负责握手、发送段和处理收到的段
func (e *endpoint) protocolMainLoop(handshake bool) *tcpip.Error {
	// ...
	
	// 处理三次握手
	if handshake {
		h, err := newHandshake(e, seqnum.Size(e.receiveBufferAvailable()))
		logger.GetInstance().Info(logger.HANDSHAKE, func() {
			log.Println("TCP STATE SENT")
		})
		if err == nil {
			// 执行握手
			err = h.execute()
		}
		// 处理握手有错
		if err != nil {
			// ...
			return err
		}

		// 到这里就表示三次握手已经成功了，那么初始化发送器和接收器
		e.snd = newSender(e, h.iss, h.ackNum-1, h.sndWnd, h.mss, h.sndWndScale)
		logger.GetInstance().Info(logger.HANDSHAKE, func() {
			log.Println("客户端握手成功 客户端的sender", e.snd)
		})

		e.rcvListMu.Lock()
		e.rcv = newReceiver(e, h.ackNum-1, h.rcvWnd, h.effectiveRcvWndScale())
		e.rcvListMu.Unlock()
	}
	
	// ...
}
```

``` go

func (h *handshake) execute() *tcpip.Error {
	// 是否需要拿到下一条地址
	if h.ep.route.IsResolutionRequired() {
		if err := h.resolveRoute(); err != nil {
			return err
		}
	}

	// Initialize the resend timer.
	// 初始化重传定时器
	resendWaker := sleep.Waker{}
	// 设置1s超时
	timeOut := time.Duration(time.Second)
	rt := time.AfterFunc(timeOut, func() {
		resendWaker.Assert()
	})
	defer rt.Stop()

	// Set up the wakers.
	s := sleep.Sleeper{}
	s.AddWaker(&resendWaker, wakerForResend)
	s.AddWaker(&h.ep.notificationWaker, wakerForNotification)
	s.AddWaker(&h.ep.newSegmentWaker, wakerForNewSegment)
	defer s.Done()

	// 开启SCAK ....

	// 表示服务端收到了syn报文
	if h.state == handshakeSynRcvd {
		synOpts.TS = h.ep.sendTSOk
		synOpts.SACKPermitted = h.ep.sackPermitted && bool(sackEnabled)
	}

	// 如果是客户端发送 syn 报文，如果是服务端发送 syn+ack 报文
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)

	for h.state != handshakeCompleted {
		// 获取事件id
		switch index, _ := s.Fetch(true); index {
		case wakerForResend: // NOTE tcp超时重传机制
			// 如果是客户端当发送 syn 报文，超过一定的时间未收到回包，触发超时重传
			// 如果是服务端当发送 syn+ack 报文，超过一定的时间未收到 ack 回包，触发超时重传
			// 超时时间变为上次的2倍 如果重传周期超过 1 分钟，返回错误，不再尝试重连
			timeOut *= 2
			if timeOut > 60*time.Second {
				return tcpip.ErrTimeout
			}
			rt.Reset(timeOut)
			// 重新发送syn|ack报文
			sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
		case wakerForNotification:

		case wakerForNewSegment: // 受到了回复
			// 对方主机的 TCP 收到 syn+ack 报文段后，还要向 本机 回复确认和上面一样，
			// tcp 的控制报文需要消耗一个字节的序列号，所以回复的 ack 序列号为 ISN2+1，发送 ack 报文给本机。
			// 处理握手报文
			if err := h.processSegments(); err != nil {
				return err
			}
		}
	}
	return nil
}
```


1. 第一次握手

首先是创建一个handshake对象，然后随机生成一个32位数字，作为同步序号。

``` go

	h := handshake{
		ep:          ep,
		active:      true,                 // 激活这个管理器
		rcvWnd:      rcvWnd,               // 初始接收窗口
		rcvWndScale: FindWndScale(rcvWnd), // 接收窗口扩展因子
	}

	// 随机一个iss(对方将收到的序号) 防止黑客搞事
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	// 初始化状态为 SynSent
	h.state = handshakeSynSent
	h.flags = flagSyn
	h.ackNum = 0
	h.mss = 0
	h.iss = seqnum.Value(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24) // 随机生成ISN2

	// 如果是客户端发送 syn 报文，如果是服务端发送 syn+ack 报文
	sendSynTCP(&h.ep.route, h.ep.id, h.flags, h.iss, h.ackNum, h.rcvWnd, synOpts)
```


2. 第二次握手

首先，我们开启了一个后台协程，这个协程会轮询acceptedChan

``` go
// protocolListenLoop 是侦听TCP端点的主循环。它在自己的goroutine中运行，负责处理连接请求
// 什么叫处理连接请求呢 其实就是 ep.Listen()时在协议栈中注册了一个Laddr+LPort的组合
// 当有客户端给服务端发送 syn 报文时 由于是新连接 所以服务端并没有相关信息
// 服务端会把这个报文交给 LAddr:LPort 的ep 去处理 也就是以下Loop
// 在验证通过后 会新建并注册一个 LAddr:LPort+RAddr:RPort的新ep 由它来处理后续的请求
func (e *endpoint) protocolListenLoop(rcvWnd seqnum.Size) *tcpip.Error {

	// 收尾处理 ...
	
	e.mu.Lock()
	v6only := e.v6only
	e.mu.Unlock()
	// 创建一个新的tcp连接
	ctx := newListenContext(e.stack, rcvWnd, v6only, e.netProto)
	// 初始化事件触发器 并添加事件

	for {
		var index int
		switch index, _ = s.Fetch(true); index { // Fetch(true) 阻塞获取
		case wakerForNewSegment:
			mayRequeue := true
			// 接收和处理tcp报文 ...
		default:
			panic((nil))
		}
	}
}

```


为了避免直面窗口滑动，我们只看服务端资源不足时，关闭窗口滑动后的连接建立。

``` go
// handleListenSegment is called when a listening endpoint receives a segment
// and needs to handle it.
func (e *endpoint) handleListenSegment(ctx *listenContext, s *segment) {
	switch s.flags {
	case flagSyn: // syn报文处理
		// 分析tcp选项
		opts := parseSynSegmentOptions(s)
		if !incSynRcvdCount() {
			s.incRef()
			go e.handleSynSegment(ctx, s, &opts)
		} else {
			// 防止半连接池攻击 我们使用cookie
			cookie := ctx.createCookie(s.id, s.sequenceNumber, encodeMSS(opts.MSS))
			synOpts := header.TCPSynOptions{
				WS:    -1, // 告知对方关闭窗口滑动
				TS:    opts.TS,
				TSVal: tcpTimeStamp(timeStampOffset()),
				TSEcr: opts.TSVal,
			}
			// 返回 syn+ack 报文 ack+1 表明我们确认了这个syn报文 占用一个字节
			sendSynTCP(&s.route, s.id, flagSyn|flagAck, cookie, s.sequenceNumber+1, ctx.rcvWnd, synOpts)
		}


	}
}
```

3. 第三次握手

客户端发送回复 ACK

``` go
	case wakerForNewSegment:
			// 对方主机的 TCP 收到 syn+ack 报文段后，还要向 本机 回复确认和上面一样，
			// tcp 的控制报文需要消耗一个字节的序列号，所以回复的 ack 序列号为 ISN2+1，发送 ack 报文给本机。
			// 处理握手报文
			if err := h.processSegments(); err != nil {
				return err
			}
		}
	
	// 报文处理
	
	if s.flagIsSet(flagAck) {
		// 客户端握手完成，发送 ack 报文给服务端
		h.state = handshakeCompleted
		// 最后依次 ack 报文丢了也没关系，因为后面一但发送任何数据包都是带ack的
		// 这里要求对端缩减窗口
		// cookie不变 seq+1 表示确认了服务端的 ack|syn 报文
		h.ep.sendRaw(buffer.VectorisedView{}, flagAck, h.iss+1, h.ackNum, h.rcvWnd>>h.effectiveRcvWndScale())
		return nil
	}
```

服务端处理ACK 新建一个tcp连接 并加入到全连接队列

``` go
	case flagAck:
		// NOTICE  对应处理后台协程过多的情况  三次握手最后一次 ack 报文
		// 当我们的后台写协程不足以处理新的连接的时候
		// 我们认为协议栈目前没有能力处理大规模数据
		// 所以我们限制后面新成立的连接的窗口尺寸

		// 验证cookie seq-1 和 ack-1 表明 还原两次握手增加的计数
		if data, ok := ctx.isCookieValid(s.id, s.ackNumber-1,
			s.sequenceNumber-1); ok && int(data) < len(mssTable) {
			// Create newly accepted endpoint and deliver it.
			rcvdSynOptions := &header.TCPSynOptions{
				MSS: mssTable[data],
				// 关闭我们的窗口滑动
				WS: -1,
			}
			if s.parsedOptions.TS {
				rcvdSynOptions.TS = true
				rcvdSynOptions.TSVal = s.parsedOptions.TSVal
				rcvdSynOptions.TSEcr = s.parsedOptions.TSEcr
			}

			// 三次握手已经完成，新建一个tcp连接
			n, err := ctx.createConnectedEndpoint(s, s.ackNumber-1,
				s.sequenceNumber-1, rcvdSynOptions)
			if err == nil {
				n.tsOffset = 0
				e.deliverAccepted(n) // 分发这个新连接到全连接队列
			}
		}
```


``` go
            c        flag       s
生成ISN1    |                   |
   sync_sent|------ isn1 0 ---->|sync_rcvd
            |                   |
            |                   |生成ISN2
 established|<--- isn2 isn+1 ---|
            |                   |
            |                   |
            |---isn1+1 isn2+1-->|established
`
```


#### 数据的发送

当我们的连接成功建立之后，我们可以直接进行全双工的通信，我们选取一个最简单的场景来演示一下。

客户端单方面发送，服务端单方面接收。

``` go
	go func() { // echo server

		listener := tcpListen(s, proto, addr, localPort)
		done <- struct{}{}
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Println(err)
			}
			log.Println("服务端 建立连接")

			go TestServerEcho(conn)
		}

	}()

	go func() {
		<-done
		port := localPort
		conn, err := Dial(s, header.IPv4ProtocolNumber, addr, port)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("客户端 建立连接\n\n客户端 写入数据\n")

		size := 1 << 10
		for i := 0; i < 3; i++ {
			conn.Write(make([]byte, size))
		}

		conn.Close()
	}()
	
func TestServerEcho(conn *TcpConn) {
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
			break
		}
		_ = n
		logger.NOTICE("服务端读取数据", string(buf[:]))
	}

	conn.ep.Close()
}

```


连接建立后，客户端写三次，然后关闭连接，服务端循环读取客户端的数据。

首先我们需要知道，tcp作为一个内核模块，是位于应用层之下的，应用层无法知悉其细节。它与应用层交流的唯一办法就是调用特定的API。那么我们从API看起。

首先是客户端写数据:

``` go
func (conn *TcpConn) Write(snd []byte) error {
	conn.wq.EventRegister(conn.we, waiter.EventOut)
	defer conn.wq.EventUnregister(conn.we)
	for {
		// 调用tcp端点的Write()
		n, _, err := conn.ep.Write(tcpip.SlicePayload(snd), tcpip.WriteOptions{To: &conn.raddr})
		if err != nil {
			// 如果返回阻塞错误 需要等待 说明底层暂时不支持继续写入
			if err == tcpip.ErrWouldBlock {
				<-conn.notifyCh // 不再阻塞 可以接续写
				if int(n) < len(snd) && n > 0 {
					snd = snd[n:]
				}
				continue
			}
			return fmt.Errorf("%s", err.String())
		}
		return nil
	}
}

```

可以发现，这个写是会阻塞的，通过一个channle进行控制。

那么我们是如何进行写数据的呢，其实我们的数据接收发送分别有两个结构来控制，负责发送的是`sender`。

``` go

type endpoint struct {
	// ...
	
	rcv *receiver // 接收器
	snd *sender // 发送器
}


func (e *endpoint) Write(p tcpip.Payload, 
	opts tcpip.WriteOptions) (uintptr, <-chan struct{}, *tcpip.Error) {
	
	// 状态校验 ...
	
	// tcp流量控制：未被占用发送缓存还剩多少，如果发送缓存已经被用光了，返回 ErrWouldBlock
	avail := e.sndBufSize - e.sndBufUsed // sndBufSize 初始化为20m
	if avail <= 0 {
		e.sndBufMu.Unlock()
		return 0, nil, tcpip.ErrWouldBlock
	}

	v, perr := p.Get(avail)
	if perr != nil {
		e.sndBufMu.Unlock()
		return 0, nil, perr
	}
	var err *tcpip.Error
	if p.Size() > avail { // 给的数据 缓存不足以容纳
		err = tcpip.ErrWouldBlock
	}
	l := len(v)
	s := newSegmentFromView(&e.route, e.id, v) // 分段
	// 插入发送队列
	e.sndBufUsed += l // 发送队列中段+1
	e.sndBufInQueue += seqnum.Size(l) // 发送队列长度+length
	e.sndQueue.PushBack(s) // 将段压入发送队列

	e.sndBufMu.Unlock()

	// 发送数据，最终会调用 sender sendData 来发送数据
	if e.workMu.TryLock() {
		// Do the work inline.
		e.handleWrite() // 消费发送队列中的数据
		e.workMu.Unlock()
	} else {
		// Let the protocol goroutine do the work.
		e.sndWaker.Assert()
	}

	return uintptr(l), nil, err

}
```

我们来直观地展示一下sender的结构

``` go

数据从左到右进行发送

                     +-------> sndWnd <-------+
                     |                        |
---------------------+-------------+----------+--------------------
|      acked         | * * * * * * | # # # # #|   unable send
---------------------+-------------+----------+--------------------
                     ^             ^
                     |             |
                   sndUna        sndNxt
*** in flight data
### able send date
```

操作发送队列，摘取发送队列压入写队列的末尾，并推动写队列写入数据

``` go
// 从发送队列中取出数据并发送出去
func (e *endpoint) handleWrite() *tcpip.Error {
	e.sndBufMu.Lock()

	// 得到第一个tcp段 注意并不是取出只是查看
	first := e.sndQueue.Front()
	if first != nil {
		// 向发送链表添加元素
		e.snd.writeList.PushBackList(&e.sndQueue)
		// NOTE 更新发送队列下一个发送字节的序号 一次性将链表全部取用
		// 当有新的数据需要发送时会有相逻辑更新这个数值
		e.snd.sndNxtList.UpdateForward(e.sndBufInQueue)
		e.sndBufInQueue = 0
	}

	e.sndBufMu.Unlock()

	// Initialize the next segment to write if it's currently nil.
	// 初始化snder的发送列表头
	if e.snd.writeNext == nil {
		e.snd.writeNext = first
	}

	// Push out any new packets.
	// 将数据发送出去
	e.snd.sendData()

	return nil
}
```

发送队列和写队列的关系

``` go

ep.sndQueue:  ...->seg3->seg2->seg1 =>

当发送队列中有数据的时候 将这个队列压入写队列 队列的队列

                                         writeNext
                                             V
ep.snd.writeList:...->seglist3->seglist2->seglist1 =>
                      ^      ^  ^      ^  ^      ^
                      |_s->s_|  |_s->s_|  |_s->s_|
					  
我们消费数据的时候找到写队列的队列头，然后遍历它

                       writeNxt(队列的指针) V
[seg2->seg1]->[seg3->seg2->seg1]->[seg3->seg2] ==> seg1
                          sndNxt(对应的字节)^         ^ sndUna(未确认的字节)
					  
```


``` go

func (s *sender) sendData() {
	limit := s.maxPayloadSize

	// 如果TCP在超过重新传输超时的时间间隔内没有发送数据，TCP应该在开始传输之前将cwnd设置为不超过RW。
	if !s.fr.active && time.Now().Sub(s.lastSendTime) > s.rto {
		if s.sndCwnd > InitialCwnd {
			s.sndCwnd = InitialCwnd
		}
	}

	var seg *segment
	end := s.sndUna.Add(s.sndWnd)
	var dataSent bool
	// 遍历发送链表，发送数据
	// tcp拥塞控制：s.outstanding < s.sndCwnd 判断正在发送的数据量不能超过拥塞窗口。
	for seg = s.writeNext; seg != nil && s.outstanding < s.sndCwnd;
		seg = seg.Next() { 
		// 如果seg的flags是0，将flags改为psh|ack
		if seg.flags == 0 {
			seg.sequenceNumber = s.sndNxt
			seg.flags = flagAck | flagPsh
		}

		var segEnd seqnum.Value
		if seg.data.Size() == 0 { // 数据段没有负载，表示要结束连接
			if s.writeList.Back() != seg {
				panic("FIN segments must be the final segment in the write list.")
			}
			// 发送 fin 报文
			seg.flags = flagAck | flagFin
			// fin 报文需要确认，且消耗一个字节序列号
			segEnd = seg.sequenceNumber.Add(1)
		} else { // 普通报文
			// We're sending a non-FIN segment.
			if seg.flags&flagFin != 0 {
				panic("Netstack queues FIN segments without data.")
			}
			if !seg.sequenceNumber.LessThan(end) { // 超过了发送窗口限制
				break
			}

			// tcp流量控制：计算最多一次发送多大数据，
			available := int(seg.sequenceNumber.Size(end))
			if available > limit {
				available = limit
			}

			// 如果seg的payload字节数大于available
			// 将seg进行分段，并且插入到该seg的后面
			// ...->[seg3->seg2->seg1]->[seg3->seg2->seg1(2048)]
			// ...->[seg3->seg2->seg1]->[seg4->seg3->seg2(1024)->seg1(1024)]
			if seg.data.Size() > available {
				nSeg := seg.clone()
				nSeg.data.TrimFront(available) // NOTE 删掉用过的
				nSeg.sequenceNumber.UpdateForward(seqnum.Size(available))
				s.writeList.InsertAfter(seg, nSeg)
				seg.data.CapLength(available)
			}

			s.outstanding++
			segEnd = seg.sequenceNumber.Add(seqnum.Size(seg.data.Size()))
		}

		if !dataSent { // 没有成功发送任何数据
			dataSent = true
			s.ep.disableKeepaliveTimer()
		}

		// 发送包 开始计算RTT
		s.sendSegment(seg.data, seg.flags, seg.sequenceNumber)
		// 发送一个数据段后，更新sndNxt
		//                              旧的 sndNxt V
		// ...->[seg3->seg2->seg1]->[seg3->seg2->seg1]
		//                         新的 sndNxt^
		if s.sndNxt.LessThan(segEnd) {
			s.sndNxt = segEnd
		}
	}
	// Remember the next segment we'll write.
	s.writeNext = seg

	// 如果重传定时器没有启动 且 sndUna != sndNxt 启动定时器
	if !s.resendTimer.enabled() && s.sndUna != s.sndNxt {
		// NOTE 开启计时器 如果在RTO后没有回信(snd.handleRecvdSegment 中有数据可以处理) 那么将会重发
		// 在 s.resendTimer.init() 中 将会调用 Assert() 唤醒重发函数 retransmitTimerExpired()
		s.resendTimer.enable(s.rto)
	}

	// NOTE 如果我们的发送窗口被缩到0 我们需要定时去问一下对端消费完了没
	if s.sndUna == s.sndNxt {
		s.ep.resetKeepaliveTimer(false)
	}
}
```


如何处理对应的ACK报文 

1. 首先对于成功确认的数据我们需要将它从写队列中摘除，并更新暂存中的段计数
2. 由于存在累积确认机制 接收方同时获取到多个连续报文的时候 将直接回复最后一个序号 而非逐个确认 所以发送方也需要以暂存区为单位处理ACK报文 
3. 如果暂存区的数据在这次数据确认过程中还有剩余 我们可能需要再次发送这些剩余数据

``` go
      writeNxt(队列的指针) V
]->[seg3->seg2->seg1]->[seg3] ==> seg2 (队列中暂存)   -seg1-(已确认 丢弃)
         sndNxt(对应的字节)^         ^ sndUna(未确认的字节)
	
因为存在还未确认的字节 对于seg2我们需要开启对应的定时重发机制


如果出现了sndNxt == sndUna 说明没数据或者不允许发送了

                 writeNxt(队列的指针) V
[                                     ]            -seg2+seg1-(已确认)
                    sndNxt(对应的字节)^sndUna(未确认的字节)

                 writeNxt(队列的指针) V
[seg2->seg1]->[seg3->seg2->seg1]->[seg3]            -seg2+seg1-(已确认)
                    sndNxt(对应的字节)^sndUna(未确认的字节)
```



``` go

// 收到段时调用 handleRcvdSegment 它负责更新与发送相关的状态
func (s *sender) handleRcvdSegment(seg *segment) {
	// 如果rtt测量seq小于ack num，更新rto
	if !s.ep.sendTSOk && s.rttMeasureSeqNum.LessThan(seg.ackNumber) {
		s.updateRTO(time.Now().Sub(s.rttMeasureTime))
		s.rttMeasureSeqNum = s.sndNxt
	}

	s.ep.updateRecentTimestamp(seg.parsedOptions.TSVal, s.maxSentAck, seg.sequenceNumber)

	// tcp的拥塞控制：检查是否有重复的ack，是否进入快速重传和快速恢复状态
	rtx := s.checkDuplicateAck(seg)

	// 存放当前窗口大小。
	s.sndWnd = seg.window
	// 获取确认号
	ack := seg.ackNumber
	// 如果ack在最小未确认的seq和segNext之间
	if (ack - 1).InRange(s.sndUna, s.sndNxt) {
		// 收到了东西 就暂停计时
		s.resendTimer.disable()

		// NOTE 一个RTT 结束
		if s.ep.sendTSOk && seg.parsedOptions.TSEcr != 0 {
			// TSVal/Ecr values sent by Netstack are at a millisecond
			// granularity.
			elapsed := time.Duration(s.ep.timestamp()-seg.parsedOptions.TSEcr) * time.Millisecond
			//logger.NOTICE("snd 424 ", elapsed.String())
			s.updateRTO(elapsed)
		}
		// 获取这次确认的字节数，即 ack - snaUna
		acked := s.sndUna.Size(ack)
		// 更新下一个未确认的序列号
		/*
      writeNxt(队列的指针) V      outstanding: 2->1
]->[seg3->seg2->seg1]->[seg3] ==> seg2 (队列中暂存)   -seg1-(已确认 丢弃)
         sndNxt(对应的字节)^         ^ sndUna(未确认的字节)
		*/
		s.sndUna = ack

		ackLeft := acked
		originalOutstanding := s.outstanding
		// 从发送链表中删除已经确认的数据，发送窗口的滑动。
		/*
		   假设我们收到了seg2开头的那个序号 我们将向后移动未确认字节到seg2
		   并从写队列中彻底删除seg1

      writeNxt(队列的指针) V
]->[seg3->seg2->seg1]->[seg3] ==> seg2 (队列中暂存)   -seg1-(已确认 丢弃)
         sndNxt(对应的字节)^         ^ sndUna(未确认的字节)
		 */
		for ackLeft > 0 { // 有成功确认的数据 丢弃它们 有剩余数据的话继续发送(根据拥塞策略控制)
			seg := s.writeList.Front()
			datalen := seg.logicalLen()

			// [##seg1##]  =>  [##] 这部分可能会重发一次
			//    ^ack
			if datalen > ackLeft {
				seg.data.TrimFront(int(ackLeft))
				break
			}

			if s.writeNext == seg {
				s.writeNext = seg.Next()
			}
			// 从发送链表中删除已确认的tcp段。
			s.writeList.Remove(seg)
			// 因为有一个tcp段确认了，所以 outstanding 减1
			s.outstanding--
			seg.decRef()
			ackLeft -= datalen
		}
		// 当收到ack确认时，需要更新发送缓冲占用
		s.ep.updateSndBufferUsage(int(acked))

		// tcp拥塞控制：如果没有进入快速恢复状态，那么根据确认的数据包的数量更新拥塞窗口。
    if !s.fr.active {
      // 调用相应拥塞控制算法的 Update
      s.cc.Update(originalOutstanding - s.outstanding)
    }

		// 如果发生超时重传时，s.outstanding可能会降到零以下，
		// 重置为零但后来得到一个覆盖先前发送数据的确认。
		if s.outstanding < 0 {
			s.outstanding = 0
		}
	}

	// tcp拥塞控制 快速重传
	if rtx {
		s.resendSegment()
	}

	// 现在某些待处理数据已被确认，或者窗口打开，或者由于快速恢复期间出现重复的ack而导致拥塞窗口膨胀，
	// 因此发送更多数据。如果需要，这也将重新启用重传计时器。
	s.sendData()
}
```




``` go
c       seq    ack      s
|                       |
|-----isn1+101 isn2+1-->| 发送100个字节 请确认 没有收到你的数据
|                       |
|                       |
|<--- isn2+1 isn+101 ---| 收到100个字节 确认了 不发送给你数据
|                       |
|                       |
|-----isn1+201 isn2+1-->| 发送100个字节  请确认 没有受到你的数据
|                       |
|                       |
|<---isn2+101 isn1+201--| 收到100个字节 确认了 发送给你100个字节
|                       |
|                       |
|---isn1+201 isn2+101-->| 收到100个字节 确认了 不发送数据给你

```



#### 连接的断开

``` go
    c     flag      s
    |               |
  1 |------fin----->|
    |               |
    |<-----ack------| 2
    |               |
    |               |
    |<-----ack------|
    |               |
    |-----ack------>|
    |               |
    |               |
    |<------fin-----| 3
    |               |
  4 |------ack----->|
    |               |
    |               |

```





