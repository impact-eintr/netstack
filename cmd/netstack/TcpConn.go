package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"netstack/logger"
	"netstack/tcpip"
	"netstack/tcpip/stack"
	"netstack/tcpip/transport/tcp"
	"netstack/waiter"
)

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

	return &TcpConn{
		ep:       ep,
		wq:       &wq,
		we:       &waitEntry,
		notifyCh: notifyCh}, nil
}

// TcpConn 一条tcp连接
type TcpConn struct {
	raddr    tcpip.FullAddress
	ep       tcpip.Endpoint
	wq       *waiter.Queue
	we       *waiter.Entry
	notifyCh chan struct{}
}

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
				logger.NOTICE("阻塞力!!!!!!!!!!!!!!!!!")
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

// SetSockOpt 设置socket属性 暂时只测试keepalive
func (conn *TcpConn) SetSockOpt(opt interface{}) error {
	err := conn.ep.SetSockOpt(opt)
	if err != nil {
		return fmt.Errorf("%s", err.String())
	}

	return nil
}

// Accept 封装tcp的accept操作
func (conn *TcpConn) Accept() (*TcpConn, error) {
	conn.wq.EventRegister(conn.we, waiter.EventIn|waiter.EventOut)
	defer conn.wq.EventUnregister(conn.we)
	for {
		ep, wq, err := conn.ep.Accept()
		if err != nil {
			if err == tcpip.ErrWouldBlock {
				<-conn.notifyCh
				continue
			}
			return nil, fmt.Errorf("%s", err.String())
		}
		waitEntry, notifyCh := waiter.NewChannelEntry(nil)
		return &TcpConn{ep: ep,
			wq:       wq,
			we:       &waitEntry,
			notifyCh: notifyCh}, nil
	}
}

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

const (
	REGISTER byte = iota
	LISTEN
	ACCEPT
	CONNECT
	READ
	WRITE
	CLOSE
)

// Register 从netstack获取pid
func Register() PID {
	// 连接本地netstack服务
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return 0
	}
	defer conn.Close()

	_, err = conn.Write([]byte{0})
	buf := make([]byte, 2)
	conn.Read(buf)

	return PID(binary.BigEndian.Uint16(buf))
}

// Listen 传递 pid addr port 监听+绑定地址
func Listen(pid PID, addr tcpip.Address, localPort int) FD {
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return 0
	}
	// 1 pid port
	buf := make([]byte, 5)
	buf[0] = LISTEN
	binary.BigEndian.PutUint16(buf[1:3], uint16(pid))
	binary.BigEndian.PutUint16(buf[3:5], uint16(localPort))
	conn.Write(buf)

	buf = make([]byte, 2)
	conn.Read(buf)
	return FD(binary.BigEndian.Uint16(buf))
}

// Accept 传递 pid + listenerfd 返回 connfd
func Accept(pid PID, lfd FD) FD {
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return 0
	}
	// 2 pid lfd
	buf := make([]byte, 5)
	buf[0] = ACCEPT
	binary.BigEndian.PutUint16(buf[1:3], uint16(pid))
	binary.BigEndian.PutUint16(buf[3:5], uint16(lfd))
	conn.Write(buf)

	buf = make([]byte, 2)
	conn.Read(buf)
	return FD(binary.BigEndian.Uint16(buf))
}

func Read(pid PID, cfd FD, rcv []byte) (int, error) {
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return 0, err
	}
	// 2 pid cfd
	buf := make([]byte, 5)
	buf[0] = READ
	binary.BigEndian.PutUint16(buf[1:3], uint16(pid))
	binary.BigEndian.PutUint16(buf[3:5], uint16(cfd))
	conn.Write(buf)

	return conn.Read(rcv)
}

func Write(pid PID, cfd FD, snd []byte) (int, error) {
	conn, err := net.Dial("tcp", "127.0.0.1:9999")
	if err != nil {
		fmt.Println("err : ", err)
		return 0, err
	}
	// 2 pid cfd
	buf := make([]byte, 9)
	buf[0] = WRITE
	binary.BigEndian.PutUint16(buf[1:3], uint16(pid))
	binary.BigEndian.PutUint16(buf[3:5], uint16(cfd))
	binary.BigEndian.PutUint32(buf[5:9], uint32(len(snd)))
	buf = append(buf, snd...)
	conn.Write(buf)

	return conn.Read(nil)
}
