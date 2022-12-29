## echo server

``` go
func main() {
	flag.Parse()
	if len(flag.Args()) != 4 {
		log.Fatal("Usage: ", os.Args[0], " <tap-device> <local-address/mask> <ip-address> <local-port>")
	}

	tapName := flag.Arg(0)
	cidrName := flag.Arg(1)
	addrName := flag.Arg(2)
	portName := flag.Arg(3)
    
    // ... 解析各种配置

	loopbackLinkID := loopback.New()

	// 新建相关协议的协议栈
	s := stack.New([]string{ipv4.ProtocolName, arp.ProtocolName},
		[]string{tcp.ProtocolName, udp.ProtocolName}, stack.Options{})

	// 新建抽象的网卡
	if err := s.CreateNamedNIC(1, "vnic1", loopbackLinkID); err != nil {
		log.Fatal(err)
	}

	// 在该协议栈上添加和注册相应的网络层
	if err := s.AddAddress(1, proto, addr); err != nil {
		log.Fatal(err)
	}

	// 在该协议栈上添加和注册ARP协议
	if err := s.AddAddress(1, arp.ProtocolNumber, arp.ProtocolAddress); err != nil {
		log.Fatal(err)
	}

	// 添加默认路由
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: tcpip.Address(strings.Repeat("\x00", len(addr))),
			Mask:        tcpip.AddressMask(strings.Repeat("\x00", len(addr))),
			Gateway:     "",
			NIC:         1,
		},
	})

	done := make(chan struct{}, 2)

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

		for i := 0; i < 3; i++ {
			conn.Write([]byte("Hello Netstack"))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf)
			if err != nil {
				log.Println(err)
				return
			}
			logger.NOTICE("客户端读取", string(buf[:n]))
		}

		conn.Close()
	}()
    
	defer close(done)
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGUSR1, syscall.SIGUSR2)
	<-c
}

func TestServerEcho(conn *TcpConn) {
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
			break
		}
		logger.NOTICE("服务端读取数据", string(buf[:n]))
		conn.Write(buf)
	}

	conn.ep.Close()
}
```


上面的代码看上去内容很多，其实并不复杂，在`done := make(chan struct{}, 2)`之前的代码是在初始化协议栈，类比的话相当于linux内核的启动，其中的内部细节并不需要用户程序了解，我们只需要关注内核对外暴露的接口即可。

随后的两个goroutine，一个是服务端，一个是客户端。

先看看服务端做了什么

``` go
go func() { // echo server
		listener := tcpListen(s, proto, addr, localPort) // 监听端口
		done <- struct{}{} // 通知客户端可以呼叫
		for {
			conn, err := listener.Accept() // 循环接受连接
			if err != nil {
				log.Println(err)
			}
			log.Println("服务端 建立连接")

			go TestServerEcho(conn) // 后台处理连接
		}

}()

// 连接的处理逻辑
func TestServerEcho(conn *TcpConn) {
	for {
		buf := make([]byte, 1024)
		n, err := conn.Read(buf) // 从连接中读数据
		if err != nil { // 当客户端关闭连接的时候 退出循环
			log.Println(err)
			break
		}
		logger.NOTICE("服务端读取数据", string(buf[:n]))
		conn.Write(buf) // 把读到的数据写回去
	}

	conn.ep.Close() // 客户端关闭后 我们退出
}
```

非常简单的一个echo server 客户端写了什么 我们就回复什么

再来看看客户端

``` go

go func() {
		<-done // 等待服务端准备完毕
		port := localPort
		conn, err := Dial(s, header.IPv4ProtocolNumber, addr, port) // 呼叫服务端 建立连接
		if err != nil {
			log.Fatal(err)
		}

        // 循环三次写入数据
		for i := 0; i < 3; i++ {
			conn.Write([]byte("Hello Netstack"))
			buf := make([]byte, 1024)
			n, err := conn.Read(buf) // 写完再读
			if err != nil {
				log.Println(err)
				return
			}
			logger.NOTICE("客户端读取", string(buf[:n]))
		}

		conn.Close() // 主动关闭连接
}()
```

我们来看看这个程序编译运行的结果

``` go
2022/12/29 14:02:15 main.go:44: tap: tap0, addr: 192.168.1.1, port: 9999
2022/12/29 14:02:15 ports.go:109: TCP 成功分配端口 9999
2022/12/29 14:02:15 connect.go:877: TCP STATE SENT
2022/12/29 14:02:15 logger.go:75: NOTICE: 告诉对端 我的接收窗口为 65535
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [syn] 报文片段到 192.168.1.1:9999, seq: 1569505920, ack: 0, 可接收rcvWnd: 65535
2022/12/29 14:02:15 accept.go:370: TCP STATE LISTEN
2022/12/29 14:02:15 accept.go:228: 收到一个远端握手申请 SYN seq = 1569505920 客户端请携带 标记 iss  710316102 +1
2022/12/29 14:02:15 accept.go:217: 服务端握手成功 服务端的recver 9999
                                             +------>   1048576 <-----+
                                             |                        |
-----------------+-------------+-------------+------------------------+
| ANR          0 | not revived |  rcvd unack |   able rcv             |
-----------------+-------------+-------------+------------------------+
^                                            ^                        ^
|                                            |                        |
1569505921                              1569505921               1570554497
2022/12/29 14:02:15 accept.go:246: TCP STATE SYN_RCVD
2022/12/29 14:02:15 logger.go:75: NOTICE: 告诉对端 我的接收窗口为 65535
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack|syn] 报文片段到 192.168.1.1:26913, seq: 710316102, ack: 1569505921, 可接收rcvWnd: 65535
2022/12/29 14:02:15 connect.go:214: 客户端收到了 syn|ack segment
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack] 报文片段到 192.168.1.1:9999, seq: 1569505921, ack: 710316103, 可接收rcvWnd: 32768
2022/12/29 14:02:15 connect.go:901: 客户端握手成功 客户端的sender 26913
                 +----->       65535  <------+
                 |    Scale     5            |
-----------------+-------------+-------------+------------------
|      已确认    |UAC         0|NXT   1048576|   不可发送
-----------------+-------------+-------------+------------------
                 ^             ^
                 |             |
             1569505921    1569505921
2022/12/29 14:02:15 main.go:163: 客户端 建立连接
2022/12/29 14:02:15 connect.go:332: TCP STATE ESTABLISHED
2022/12/29 14:02:15 main.go:148: 服务端 建立连接
2022/12/29 14:02:15 logger.go:75: NOTICE: 扩张发送窗口到 1048576

客户端 写入数据
2022/12/29 14:02:15 snd.go:586: 发送窗口是 65535 最多发送数据 65483 缓存数据头 1569505921 缓存数据尾 1569505935 发送端缓存包数量 1 拥塞窗口为 10
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack|psh] 报文片段到 192.168.1.1:9999, seq: 1569505921, ack: 710316103, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 26913  更新sndNxt 1569505921  为  1569505935 下一次发送的数据头为 1569505935
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack] 报文片段到 192.168.1.1:26913, seq: 710316103, ack: 1569505935, 可接收rcvWnd: 32767
2022/12/29 14:02:15 logger.go:75: NOTICE: 服务端读取数据 Hello Netstack


2022/12/29 14:02:15 snd.go:586: 发送窗口是 1048576 最多发送数据 65483 缓存数据头 710316103 缓存数据尾 710317127 发送端缓存包数量 1 拥塞窗口为 10
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack|psh] 报文片段到 192.168.1.1:26913, seq: 710316103, ack: 1569505935, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 9999  更新sndNxt 710316103  为  710317127 下一次发送的数据头为 710317127
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack] 报文片段到 192.168.1.1:9999, seq: 1569505935, ack: 710317127, 可接收rcvWnd: 32736
2022/12/29 14:02:15 logger.go:75: NOTICE: 客户端读取 Hello Netstack


2022/12/29 14:02:15 snd.go:586: 发送窗口是 1048576 最多发送数据 65483 缓存数据头 1569505935 缓存数据尾 1569505949 发送端缓存包数量 1 拥塞窗口为 11
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack|psh] 报文片段到 192.168.1.1:9999, seq: 1569505935, ack: 710317127, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 26913  更新sndNxt 1569505935  为  1569505949 下一次发送的数据头为 1569505949
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack] 报文片段到 192.168.1.1:26913, seq: 710317127, ack: 1569505949, 可接收rcvWnd: 32767
2022/12/29 14:02:15 logger.go:75: NOTICE: 服务端读取数据 Hello Netstack


2022/12/29 14:02:15 snd.go:586: 发送窗口是 1048576 最多发送数据 65483 缓存数据头 710317127 缓存数据尾 710318151 发送端缓存包数量 1 拥塞窗口为 11
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack|psh] 报文片段到 192.168.1.1:26913, seq: 710317127, ack: 1569505949, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 9999  更新sndNxt 710317127  为  710318151 下一次发送的数据头为 710318151
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack] 报文片段到 192.168.1.1:9999, seq: 1569505949, ack: 710318151, 可接收rcvWnd: 32736
2022/12/29 14:02:15 logger.go:75: NOTICE: 客户端读取 Hello Netstack


2022/12/29 14:02:15 snd.go:586: 发送窗口是 1048576 最多发送数据 65483 缓存数据头 1569505949 缓存数据尾 1569505963 发送端缓存包数量 1 拥塞窗口为 12
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack|psh] 报文片段到 192.168.1.1:9999, seq: 1569505949, ack: 710318151, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 26913  更新sndNxt 1569505949  为  1569505963 下一次发送的数据头为 1569505963
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack] 报文片段到 192.168.1.1:26913, seq: 710318151, ack: 1569505963, 可接收rcvWnd: 32767
2022/12/29 14:02:15 logger.go:75: NOTICE: 服务端读取数据 Hello Netstack


2022/12/29 14:02:15 snd.go:586: 发送窗口是 1048576 最多发送数据 65483 缓存数据头 710318151 缓存数据尾 710319175 发送端缓存包数量 1 拥塞窗口为 12
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack|psh] 报文片段到 192.168.1.1:26913, seq: 710318151, ack: 1569505963, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 9999  更新sndNxt 710318151  为  710319175 下一次发送的数据头为 710319175
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack] 报文片段到 192.168.1.1:9999, seq: 1569505963, ack: 710319175, 可接收rcvWnd: 32736
2022/12/29 14:02:15 logger.go:75: NOTICE: 客户端读取 Hello Netstack


2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack|fin] 报文片段到 192.168.1.1:9999, seq: 1569505963, ack: 710319175, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 26913  更新sndNxt 1569505963  为  1569505964 下一次发送的数据头为 1569505964
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack] 报文片段到 192.168.1.1:26913, seq: 710319175, ack: 1569505964, 可接收rcvWnd: 32768
2022/12/29 14:02:15 main.go:202: endpoint is closed for receive
2022/12/29 14:02:15 connect.go:608: TCP :9999 发送 [ack|fin] 报文片段到 192.168.1.1:26913, seq: 710319175, ack: 1569505964, 可接收rcvWnd: 32768
2022/12/29 14:02:15 snd.go:603: 9999  更新sndNxt 710319175  为  710319176 下一次发送的数据头为 710319176
2022/12/29 14:02:15 connect.go:608: TCP :26913 发送 [ack] 报文片段到 192.168.1.1:9999, seq: 1569505964, ack: 710319176, 可接收rcvWnd: 32768

```

为了看得清楚一点，我将结果分了几个段，我们可以看到，在每个段的最后一行有 服务端/客户端 读取 Hello Netstack 数量也符合我们的程序逻辑

## 接口

在上面的程序中，我们可以发现和正常的网络编程不同，我使用了一些不同于go/net库的函数。

``` go
TcpListen()

Dial()

...
```


这些函数是我自己封装的，用于隐藏底层对协议栈的复杂操作。但这个封装是非常简陋的，仅仅是能测试而已，但我们先就用这个来简单说说。

首先是一个结构体，表示一条tcp的连接。

``` go
// TcpConn 一条tcp连接
type TcpConn struct {
	raddr    tcpip.FullAddress
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	we       *waiter.Entry
	notifyCh chan struct{}
}
```


对于服务端而言，它是这样建立的

``` go
func tcpListen(s *stack.Stack, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, localPort int) *TcpConn {
	var wq waiter.Queue
	// 新建一个tcp端
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		log.Fatal(err)
	}

	// 绑定IP和端口，这里的IP地址为空，表示绑定任何IP
	// 此时就会调用端口管理器
	if err := ep.Bind(tcpip.FullAddress{NIC: 1, Addr: "", Port: uint16(localPort)}, nil); err != nil {
		log.Fatal("Bind failed: ", err)
	}

	// 开始监听
	if err := ep.Listen(10); err != nil {
		log.Fatal("Listen failed: ", err)
	}

	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	return &TcpConn{
		ep:       ep,
		wq:       &wq,
		we:       &waitEntry,
		notifyCh: notifyCh}
}
```


对于客户端而言，它是这样建立的

``` go
// Dial 呼叫tcp服务端
func Dial(s *stack.Stack, proto tcpip.NetworkProtocolNumber, addr tcpip.Address, port int) (*TcpConn, error) {
	remote := tcpip.FullAddress{
		Addr: addr,
		Port: uint16(port),
	}
	var wq waiter.Queue
	waitEntry, notifyCh := waiter.NewChannelEntry(nil)
	wq.EventRegister(&waitEntry, waiter.EventOut)
	defer wq.EventUnregister(&waitEntry)
	// 新建一个tcp端
	ep, err := s.NewEndpoint(tcp.ProtocolNumber, proto, &wq)
	if err != nil {
		return nil, fmt.Errorf("%s", err.String())
	}
	err = ep.Connect(remote)
	if err != nil {
		if err == tcpip.ErrConnectStarted {
			<-notifyCh
		} else {
			return nil, fmt.Errorf("%s", err.String())
		}
	}

	ep.SetSockOpt(tcpip.KeepaliveEnabledOption(1))
	ep.SetSockOpt(tcpip.KeepaliveIntervalOption(75 * time.Second))
	ep.SetSockOpt(tcpip.KeepaliveIdleOption(30 * time.Second)) // 30s的探活心跳
	ep.SetSockOpt(tcpip.KeepaliveCountOption(9))

	return &TcpConn{
		ep:       ep,
		wq:       &wq,
		we:       &waitEntry,
		notifyCh: notifyCh}, nil
}
```


数据的读写

``` go
// Read 读数据
func (conn *TcpConn) Read(rcv []byte) (int, error) {
	conn.wq.EventRegister(conn.we, waiter.EventIn)
	defer conn.wq.EventUnregister(conn.we)
	for {
		buf, _, err := conn.ep.Read(&conn.raddr)
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-conn.notifyCh
				continue
			}
			return 0, fmt.Errorf("%s", err.String())
		}
		n := len(buf)
		if n > cap(rcv) {
			n = cap(rcv)
		}
		rcv = append(rcv[:0], buf[:n]...)
		return len(buf), nil
	}
}

// Write 写数据
func (conn *TcpConn) Write(snd []byte) error {
	conn.wq.EventRegister(conn.we, waiter.EventOut)
	defer conn.wq.EventUnregister(conn.we)
	for {
		n, _, err := conn.ep.Write(tcpip.SlicePayload(snd), tcpip.WriteOptions{To: &conn.raddr})
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-conn.notifyCh
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

// Close 关闭连接
func (conn *TcpConn) Close() {
	conn.ep.Close()
}
```
