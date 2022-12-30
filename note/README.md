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
	go e.dispatchLoop()
    
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

这个`FindRoute`就是在写入syn报文前寻找目标mac


``` go

// FindRoute 路由查找实现，比如当tcp建立连接时，会用该函数得到路由信息
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

#### 缓存的设计
