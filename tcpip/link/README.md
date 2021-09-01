# 链路层
## 链路层的介绍和基本实现
本节主要介绍链路层的基本实现，主要讲以太网网卡、虚拟网卡和 arp 协议。

### 链路层的目的
数据链路层属于计算机网络的底层，使用的信道主要有点对点信道和广播信道两种类型。 在 TCP/IP 协议族中，数据链路层主要有以下几个目的：

1. 接收和发送链路层数据，提供 io 的能力。
2. 为 IP 模块发送和接收数据
3. 为 ARP 模块发送 ARP 请求和接收 ARP 应答
4. 为 RARP 模块发送 RARP 请求和接收 RARP 应答

**TCP/IP 支持多种不同的链路层协议，这取决于网络所使用的硬件。**
数据链路层的协议数据单元——`帧`：将 IP 层（网络层）的数据报添加首部和尾部封装成帧。 
数据链路层协议有许多种，都会解决三个基本问题，封装成帧，透明传输，差错检测。

### 以太网介绍
我们这章讲的是链路层，为何要讲以太网，那是因为以太网实在应用太广了，以至于我们在现实生活中看到的链路层协议的数据封装都是以太网协议封装的，所以要实现链路层数据的处理，我们必须要了解以太网。

以太网（Ethernet）是一种计算机局域网技术。IEEE 组织的 IEEE 802.3 标准制定了以太网的技术标准，它规定了包括物理层的连线、电子信号和介质访问层协议的内容。以太网是目前应用最普遍的局域网技术，取代了其他局域网标准如令牌环、FDDI 和 ARCNET。以太网协议，是当今现有局域网采用的最通用的通信协议标准，故可认为以太网就是局域网。

### 链路层的寻址
通信当然得知道发送者的地址和接受者的地址，这是最基础的。以太网规定，所有连入网络的设备，都必须具有“网卡”接口。然后**数据包是从一块网卡，传输到另一块网卡的**。网卡的地址，就是数据包的发送地址和接收地址，叫做 MAC 地址，也叫物理地址，这是最底层的地址。每块网卡出厂的时候，都有一个全世界独一无二的 MAC 地址，长度是 48 个二进制位，通常用 12 个十六进制数表示。有了这个地址，我们可以定位网卡和数据包的路径了。

### MTU（最大传输单元）
**MTU 表示在链路层最大的传输单元，也就是链路层一帧数据的数据内容最大长度，单位为字节**，MTU 是协议栈实现一个很重要的参数，请大家务必理解该参数。一般网卡默认 MTU 是 1500，当你往网卡写入的内容超过 1518bytes，就会报错，后面我们可以写代码试试。

![img](img/document-uid949121labid10418timestamp1555399038307.png )
上面的图片是 linux 上链路层的实现，链路层的实现可以分为三层，真实的以太网卡，网卡驱动，网卡逻辑抽象。

真实的网卡我们不关心，因为那是硬件工程，我们只需要知道，它能接收和发送网络数据给网卡驱动就好了。网卡驱动我们也不关心，一般驱动都是网卡生产商就写好了，我们只需知道，它能接收协议栈的数据发送给网卡，接收网卡的数据发送给协议栈。网卡逻辑抽象表示，这个是我们关心的，我需要对真实的网卡进行抽象，

在系统中表示，也需要对抽象的网卡进行管理。

> 注意：后面系统中网卡的逻辑抽象我们都描述为网卡。

比如在 linux 上，当你敲下 ifconfig 命令，会输出类似如下内容：

``` bash
eth0      Link encap:Ethernet  HWaddr 00:16:3e:08:a1:7a
          inet addr:172.18.153.158  Bcast:172.18.159.255  Mask:255.255.240.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:285941546 errors:0 dropped:0 overruns:0 frame:0
          TX packets:281609568 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:142994767953 (142.9 GB)  TX bytes:44791940275 (44.7 GB)

lo        Link encap:Local Loopback
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:363350690 errors:0 dropped:0 overruns:0 frame:0
          TX packets:363350690 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1
          RX bytes:28099158493 (28.0 GB)  TX bytes:28099158493 (28.0 GB)
```

示例里显示了两个网卡，一个 eth0 以太网网卡，一个 lo 本地回环网卡。还可以看到两个网卡的信息，当我们要表示一个网卡的时候，需要具备几个属性：

1. 网卡的名字、类型和 MAC 地址
- eth0 Link encap:Ethernet HWaddr 00:16:3e:08:a1:7a
    - eth0是网卡名，方便表示一个网卡，网卡名在同个系统里不能重复
    - Link encap:Ethernet 表示该网卡类型为以太网网卡。
    - HWaddr 00:16:3e:08:a1:7a 表示 MAC 地址 00:16:3e:08:a1:7a，是链路层寻址的地址。
2. 网卡的 IP 地址及掩码
- inet addr:172.18.153.158 Bcast:172.18.159.255 Mask:255.255.240.0
  - inet addr:172.18.153.158 表示该网卡的 ipv4 地址是 172.18.153.158。
  - Bcast:172.18.159.255 表示该网卡 ip 层的广播地址。
  - 255.255.240.0 该网卡的子网掩码。
3. 网卡的状态和 MTU
- UP BROADCAST RUNNING MULTICAST MTU:1500 Metric:1
    - UP BROADCAST RUNNING MULTICAST都是表示网卡的状态
      - UP（代表网卡开启状态） 
      - BROADCAST (支持广播) 
      - RUNNING（代表网卡的网线被接上）
      - MULTICAST（支持组播）。
    - MTU:1500 最大传输单元为 1500 字节。
    - Metric:1 接口度量值为 1，接口度量值表示在这个路径上发送一个分组的成本。

### linux的虚拟网卡介绍
实现协议栈，我们需要一个网卡，因为这样我们才能接收和发送网络数据，但是一般情况下，我们电脑的操作系统已经帮我们管理好网卡了，我们想实现自由的控制网卡是不太方便的，还好 linux 系统还有另一个功能-虚拟网卡，它是操作系统虚拟出来的一个网卡，我们协议栈的实现都是基于虚拟网卡，用虚拟网卡的好处是：

对于用户来说虚拟网卡和真实网卡几乎没有差别，而且我们控制或更改虚拟网卡大部分情况下不会影响到真实的网卡，也就不会影响到用户的网络。
虚拟网卡的数据可以直接从用户态直接读取和写入，这样我们就可以直接在用户态编写协议栈。
Linux 中虚拟网络设备
TUN/TAP 设备、VETH 设备、Bridge 设备、Bond 设备、VLAN 设备、MACVTAP 设备，下面我们只讲 tun/tap 设备，其他虚拟设备感兴趣的同学可以去网上自行搜索。

TAP/TUN 设备是一种让用户态和内核之间进行数据交换的虚拟设备，TAP 工作在二层，TUN 工作在三层，TAP/TUN 网卡的两头分别是内核网络协议栈和用户层,其作用是将协议栈中的部分数据包转发给用户空间的应用程序，给用户空间的程序一个处理数据包的机会。

当我们想在 linux 中创建一个 TAP 设备时，其实很容易，像普通文件一样打开字符设备 /dev/net/tun 可以得到一个文件描述符，接着用系统调用 ioctl 将文件描述符和 kernel 的 tap 驱动绑定在一起，那么之后对该文件描述符的读写就是对虚拟网卡 TAP 的读写。详细的实现可以看 (tuntap)[https://www.kernel.org/doc/Documentation/networking/tuntap.txt] 所以最终我们实现的协议栈和 TAP 虚拟网卡的关系，如下图：

 `userland netstack` <- `tap` <- kernel`

### tap网卡实验
在 linux 中创建虚拟网卡，我们可以用 linux 自带的 ip 命令来实现，关于 ip 命令的更多用法请看 man ip。

创建 tap 网卡

#### 创建一个tap模式的虚拟网卡tap0

``` bash

sudo ip tuntap add mode tap tap0
```

#### 开启该网卡

``` bash

sudo ip link set tap0 up
```

#### 设置该网卡的ip及掩码

``` bash

sudo ip addr add 192.168.1.1/24 dev tap0
```

我们创建一个为名 tap0，ip 及掩码为 192.168.1.1/24 的虚拟网卡，执行 ifconfig 看看，会看到一个 tap0 的网卡：

``` bash
tap0      Link encap:Ethernet  HWaddr 22:e2:f2:93:ff:bf
          inet addr:192.168.1.1  Bcast:0.0.0.0  Mask:255.255.255.0
          UP BROADCAST MULTICAST  MTU:1500  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)
 
```

         

删除网卡可以使用如下命令：

#### 删除虚拟网卡

``` bash

sudo ip tuntap del mode tap tap0
```

看起来和真实的网卡没有任何区别，接下来我们自己用 golang 来实现创建网卡。

golang 创建 tuntap 网卡的库实现，在 netstack/tcpip/link/tuntap 目录下可以查看源文件 tuntap.go 的代码：

``` go
// +build linux

package tuntap

import (
    "errors"
    "fmt"
    "os/exec"
    "syscall"
    "unsafe"
)

const (
    TUN = 1
    TAP = 2
)

var (
    ErrDeviceMode = errors.New("unsupport device mode")
)

type rawSockaddr struct {
    Family uint16
    Data   [14]byte
}

// 虚拟网卡设置的配置
type Config struct {
    Name string // 网卡名
    Mode int    // 网卡模式，TUN or TAP
}

// NewNetDev根据配置返回虚拟网卡的文件描述符
func NewNetDev(c *Config) (fd int, err error) {
    switch c.Mode {
    case TUN:
        fd, err = newTun(c.Name)
    case TAP:
        fd, err = newTAP(c.Name)
    default:
        err = ErrDeviceMode
        return
    }
    if err != nil {
        return
    }
    return
}

// SetLinkUp 让系统启动该网卡
func SetLinkUp(name string) (err error) {
    // ip link set <device-name> up
    out, cmdErr := exec.Command("ip", "link", "set", name, "up").CombinedOutput()
    if cmdErr != nil {
        err = fmt.Errorf("%v:%v", cmdErr, string(out))
        return
    }
    return
}

// SetRoute 通过ip命令添加路由
func SetRoute(name, cidr string) (err error) {
    // ip route add 192.168.1.0/24 dev tap0
    out, cmdErr := exec.Command("ip", "route", "add", cidr, "dev", name).CombinedOutput()
    if cmdErr != nil {
        err = fmt.Errorf("%v:%v", cmdErr, string(out))
        return
    }
    return
}

// AddIP 通过ip命令添加IP地址
func AddIP(name, ip string) (err error) {
    // ip addr add 192.168.1.1 dev tap0
    out, cmdErr := exec.Command("ip", "addr", "add", ip, "dev", name).CombinedOutput()
    if cmdErr != nil {
        err = fmt.Errorf("%v:%v", cmdErr, string(out))
        return
    }
    return
}

func GetHardwareAddr(name string) (string, error) {
    fd, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_DGRAM, 0)
    if err != nil {
        return "", err
    }

    defer syscall.Close(fd)

    var ifreq struct {
        name [16]byte
        addr rawSockaddr
        _    [8]byte
    }

    copy(ifreq.name[:], name)
    _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.SIOCGIFHWADDR, uintptr(unsafe.Pointer(&ifreq)))
    if errno != 0 {
        return "", errno
    }

    mac := ifreq.addr.Data[:6]
    return string(mac[:]), nil
}

// newTun新建一个tun模式的虚拟网卡，然后返回该网卡的文件描述符
// IFF_NO_PI表示不需要包信息
func newTun(name string) (int, error) {
    return open(name, syscall.IFF_TUN|syscall.IFF_NO_PI)
}

// newTAP新建一个tap模式的虚拟网卡，然后返回该网卡的文件描述符
func newTAP(name string) (int, error) {
    return open(name, syscall.IFF_TAP|syscall.IFF_NO_PI)
}

// 先打开一个字符串设备，通过系统调用将虚拟网卡和字符串设备fd绑定在一起
func open(name string, flags uint16) (int, error) {
    // 打开tuntap的字符设备，得到字符设备的文件描述符
    fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
    if err != nil {
        return -1, err
    }

    var ifr struct {
        name  [16]byte
        flags uint16
        _     [22]byte
    }

    copy(ifr.name[:], name)
    ifr.flags = flags
    // 通过ioctl系统调用，将fd和虚拟网卡驱动绑定在一起
    _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
    if errno != 0 {
        syscall.Close(fd)
        return -1, errno
    }
    return fd, nil
}
```

根据这个库，我们写一个从网卡读取数据的程序，并打印读取到的字节数。新建文件 tcpip/lab/link/tap1/main.go，输入如下代码：

``` go
package main

import (
    "log"
    "tcpip/netstack/tcpip/link/rawfile"
    "tcpip/netstack/tcpip/link/tuntap"
)

func main() {
    tapName := "tap0"
    c := &tuntap.Config{tapName, tuntap.TAP}
    fd, err := tuntap.NewNetDev(c)
    if err != nil {
        panic(err)
    }

    // 启动tap网卡
    _ = tuntap.SetLinkUp(tapName)
    // 添加ip地址
    _ = tuntap.AddIP(tapName, "192.168.1.1/24")

    buf := make([]byte, 1<<16)
    for {
        rn, err := rawfile.BlockingRead(fd, buf)
        if err != nil {
            log.Println(err)
            continue
        }
        log.Printf("read %d bytes", rn)
    }
}
```


copy
然后进入目录 tcpip/lab/link/tap1 编译代码。

``` bash

cd ~/tcpip/lab/link/tap1/
go build
```

会生成一个叫 tap1 的可执行文件，我们执行它

``` bash

sudo ./tap1
```

稍等一会再打开另一个终端，利用 tcpdump 抓取经过 tap0 网卡的数据，如果执行 tap1，立马就抓包，可能会抓到一些 ipv6 的组播包，我们这里先忽略。

``` bash

sudo tcpdump -i tap0 -n
```

再打开另一个终端，我们试 ping 一下 192.168.1.1

``` bash

ping 192.168.1.1
```


但是 tcpdump 抓取数据的终端和我们自己写的打印网卡数据的终端中没有任何 icmp 数据，这是为何？这是因为当给一个网卡添加 ip 地址的时候，系统会将相应的路由添加到“本地路由表”，正因为这样，即使看起来 192.168.1.1 是 tap0 网卡的地址，但实际上我们 ping 的数据并没有走到 tap0 网卡，而是在 lo 网卡上，我们可以试试在终端抓去 lo 网卡数据

``` bash

sudo tcpdump src 192.168.1.1 -i lo -n
```

再 ping 一下 192.168.1.1 ，查看 tcpdump 的输出：

``` bash
listening on lo, link-type EN10MB (Ethernet), capture size 262144 bytes
22:40:18.028585 IP 192.168.1.1 > 192.168.1.1: ICMP echo request, id 29728, seq 1, length 64
22:40:18.028599 IP 192.168.1.1 > 192.168.1.1: ICMP echo reply, id 29728, seq 1, length 64
22:40:19.029912 IP 192.168.1.1 > 192.168.1.1: ICMP echo request, id 29728, seq 2, length 64
22:40:19.029925 IP 192.168.1.1 > 192.168.1.1: ICMP echo reply, id 29728, seq 2, length 64
```

查看本地路由的信息，通过 ip route show table local 命令。

``` bash
broadcast 10.211.55.0 dev enp0s5  proto kernel  scope link  src 10.211.55.14
broadcast 10.211.55.0 dev enp0s6  proto kernel  scope link  src 10.211.55.16
local 10.211.55.14 dev enp0s5  proto kernel  scope host  src 10.211.55.14
local 10.211.55.16 dev enp0s6  proto kernel  scope host  src 10.211.55.16
broadcast 10.211.55.255 dev enp0s5  proto kernel  scope link  src 10.211.55.14
broadcast 10.211.55.255 dev enp0s6  proto kernel  scope link  src 10.211.55.16
broadcast 127.0.0.0 dev lo  proto kernel  scope link  src 127.0.0.1
local 127.0.0.0/8 dev lo  proto kernel  scope host  src 127.0.0.1
local 127.0.0.1 dev lo  proto kernel  scope host  src 127.0.0.1
broadcast 127.255.255.255 dev lo  proto kernel  scope link  src 127.0.0.1
broadcast 192.168.1.0 dev tap0  proto kernel  scope link  src 192.168.1.1
local 192.168.1.1 dev tap0  proto kernel  scope host  src 192.168.1.1
broadcast 192.168.1.255 dev tap0  proto kernel  scope link  src 192.168.1.1

```

可以看到倒数第二行，表示了 192.168.1.1 这个地址，在 local 路由表里。同时路由表也显示，只有 192.168.1.1 这个地址在路由表里，该网段的其他地址不在本地路由，那么应该会进入 tap0 网卡，比如我们试试 192.168.1.2 这个地址，ping 一下

``` bash

PING 192.168.1.2 (192.168.1.2) 56(84) bytes of data.
From 192.168.1.1 icmp_seq=1 Destination Host Unreachable
From 192.168.1.1 icmp_seq=2 Destination Host Unreachable
```

然后 tcpdump 在 tap0 网卡上的输出

``` bash

listening on tap0, link-type EN10MB (Ethernet), capture size 262144 bytes
22:55:58.322022 ARP, Request who-has 192.168.1.2 tell 192.168.1.1, length 28
22:55:59.320824 ARP, Request who-has 192.168.1.2 tell 192.168.1.1, length 28
```

说明 tap0 网卡收到了 arp 请求，至于我们使用 ping 之后为何接收到的是 arp 请求报文而不是 icmp 报文，这是因为系统不知道 192.168.1.2 的 MAC 地址，后面会详细说明。

在上面的程序中，我们也可以看到上面的程序有打印：

``` bash
2018/11/11 23:54:10 read 42 bytes
2018/11/11 23:54:11 read 42 bytes
2018/11/11 23:54:12 read 42 bytes
2018/11/11 23:54:13 read 42 bytes

```

其实在链路层通信，是可以不需要 ip 地址的，我们可以手动配置路由，将数据导入虚拟网卡，现在更改我们的程序，代码存放在 tcpip/lab/link/tap2/main.go：

``` go
package main

import (
    "log"
    "tcpip/netstack/tcpip/link/rawfile"
    "tcpip/netstack/tcpip/link/tuntap"
)

func main() {
    tapName := "tap0"
    c := &tuntap.Config{tapName, tuntap.TAP}
    fd, err := tuntap.NewNetDev(c)
    if err != nil {
        panic(err)
    }

    // 启动tap网卡
    _ = tuntap.SetLinkUp(tapName)
    // 设置路由
    _ = tuntap.SetRoute(tapName, "192.168.1.0/24")

    buf := make([]byte, 1<<16)
    for {
        rn, err := rawfile.BlockingRead(fd, buf)
        if err != nil {
            log.Println(err)
            continue
        }
        log.Printf("read %d bytes", rn)
    }
}
```


进入目录 tcpip/lab/link/tap2，然后编译代码。

``` bash
cd ~/tcpip/lab/link/tap2

go build
```

会生成一个叫tap2的可执行文件，我们执行它

``` bash

sudo ./tap2
```

稍等一会再打开另一个终端，利用 tcpdump 抓取经过 tap0 网卡的数据。

``` bash

sudo tcpdump -i tap0 -n
```

再打开另一个终端，我们试 ping 一下 192.168.1.1

``` bash

ping 192.168.1.1
```

查看程序 tap2 的输出：

``` bash
2019/04/10 11:12:57 read 42 bytes
2019/04/10 11:12:58 read 42 bytes
2019/04/10 11:12:59 read 42 bytes
2019/04/10 11:13:16 read 42 bytes
2019/04/10 11:13:17 read 42 bytes
2019/04/10 11:13:18 read 42 bytes

```

这时候你 ping 192.168.1.0/24 网段的任何一个地址都是进入 tap0 网卡，这样我们就可以实验和处理 tap0 网上上的数据了。目前我们只看到了网卡有读取到数据，而且抓包显示我们现在接收到的数据都是 arp 请求，后面会实现对 arp 报文的处理，接下来我们开始处理网卡的数据并封装链路层，实现网卡的 io。
