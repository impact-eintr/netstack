# 网络层的基本实现

本章介绍网络层的实现，网络层又称网际层、ip 层，它是 tcpip 架构中核心的实现，全球计算机的互联很大部分归功于网络层，核心网络（路由器）都跑在网络层，为网络提供路由交换的功能，将数据包分发到相应的主机。虽然网络层在路由器上的实现比较复杂，因为要实现各种路由协议，但主机协议栈中的网络层并不复杂，因为它没有实现各种路由协议，路由表也很简单。下面介绍网络层提供的服务和实现网络层的 ip 协议-ipv4。

## 网络层提供的服务
在计算机网络领域，曾经为网络层应该提供怎样的服务（面向连接还是无连接）引起了长时间的争论。最终因特网采用的设计思路是：网络层向上提供简单灵活的、无连接的、尽最大努力交付的数据报服务。所谓的数据报服务具有以下几个特点：

1. 无需建立连接
2. 不保证可靠性
3. 每个分组都有终点的完整地址
4. 每个分组独立选择路由进行转发
5. 可靠通信应该有上层负责 网络层的目的是实现两个主机之间的数据透明传送，具体功能包括寻址和路由选择等。它提供的服务使传输层不需要了解网络中的数据传输和交换技术。对网络层而言使用一种逻辑地址来唯一标识互联网上的设备，网络层依靠逻辑地址进行相互通信（类似于数据链路层的 MAC 地址），逻辑地址编址方案现主要有两种，IPv4 和 IPv6，我们主要讲协议栈对 IPv4 协议的处理。一般我们说 IP 地址，指的是 ipv4 地址。

## 网络层和链路层的功能区别
之前讲过链路层也可以实现主机到主机的数据透明传输，那为何还需要网络层实现主机到主机的数据传输？

因为链路层的数据交换是在同个局域网实现的，链路层的交换也就是二层交换，它依赖二层广播 ARP 报文，来学习 MAC 地址和端口的对应关系。当交换机从某个端口收到一个数据包，它会先读取包中的源 MAC 地址，再去读取包中的目的 MAC 地址，并在地址表中查找对应的端口，如表中有和目的 MAC 地址对应的端口，就把数据包直接复制到这个端口上。链路层其最基本的服务是将源自网络层来的数据可靠地传输到相邻节点的目标机网络层。

而网络层的数据交换是不限于局域网的，网络层连接着因特网中各局域网、广域网的设备，是互联网络的枢纽。网络层的数据交换（路由交换）是根据目的 IP，查找路由表找到下一跳的 IP 地址，再根据这个下一跳 IP 地址，查找转发表，将数据包转发给相应的端口。简单的说链路层的寻址关心 MAC 地址而不管数据包中的 IP 地址，而网络层的寻址关心 IP 地址，而不关心 MAC 地址，链路层和网络层的结合实现了世界上两台主机的数据互相传输。

## ipv4简介

IPv4，是互联网协议（Internet Protocol，IP）的第四版，也是第一个被广泛使用，构成现今互联网技术的基础的协议。IPv4 是一种无连接的协议，操作在使用分组交换的链路层（如以太网）上。此协议会尽最大努力交付数据包，意即它不保证任何数据包均能送达目的地，也不保证所有数据包均按照正确的顺序无重复地到达。这些方面是由上层的传输协议（如传输控制协议）处理的。

## ip报文

- IPv4，是互联网协议（Internet Protocol，IP）的第四版，也是第一个被广泛使用，构成现今互联网技术的基础的协议。IPv4 是一种无连接的协议，操作在使用分组交换的链路层（如以太网）上。此协议会尽最大努力交付数据包，意即它不保证任何数据包均能送达目的地，也不保证所有数据包均按照正确的顺序无重复地到达。这些方面是由上层的传输协议（如传输控制协议）处理的。

- 版本（Version） 版本字段占 4bit，通信双方使用的版本必须一致。对于 IPv4，字段的值是 4。

- 首部长度（Internet Header Length， IHL） 占 4bit，首部长度说明首部有多少 32 位字（4 字节）。由于 IPv4 首部可能包含数目不定的选项，这个字段也用来确定数据的偏移量。这个字段的最小值是 5（二进制 0101），相当于 5*4=20 字节（RFC 791），最大十进制值是 15。

- 区分服务（Differentiated Services，DS） 占 8bit，最初被定义为服务类型字段，实际上并未使用，但 1998 年被 IETF 重定义为区分服务 RFC 2474。只有在使用区分服务时，这个字段才起作用，在一般的情况 下都不使用这个字段。例如需要实时数据流的技术会应用这个字段，一个例子是 VoIP。

- 显式拥塞通告（ Explicit Congestion Notification，ECN） 在 RFC 3168 中定义，允许在不丢弃报文的同时通知对方网络拥塞的发生。ECN 是一种可选的功能，仅当两端都支持并希望使用，且底层网络支持时才被使用。

- 全长（Total Length） 这个 16 位字段定义了报文总长，包含首部和数据，单位为字节。这个字段的最小值是 20（20 字节首部+0 字节数据），最大值是 2^16-1=65,535。IP 规定所有主机都必须支持最小 576 字节的报文，这是假定上层数据长度 512 字节，加上最长 IP 首部 60 字节，加上 4 字节富裕量，得出 576 字节，但大多数现代主机支持更大的报文。**当下层的数据链路协议的最大传输单元（MTU）字段的值小于 IP 报文长度时，报文就必须被分片，详细见下个标题。**

- 标识符（Identification） 占 16 位，这个字段主要被用来唯一地标识一个报文的所有分片，因为分片不一定按序到达，所以在重组时需要知道分片所属的报文。每产生一个数据报，计数器加 1，并赋值给此字段。一些实验性的工作建议将此字段用于其它目的，例如增加报文跟踪信息以协助探测伪造的源地址。

- 标志 （Flags） 这个 3 位字段用于控制和识别分片，它们是： 位 0：保留，必须为 0； 位 1：禁止分片（Don’t Fragment，DF），当 DF=0 时才允许分片； 位 2：更多分片（More Fragment，MF），MF=1 代表后面还有分片，MF=0 代表已经是最后一个分片。 如果 DF 标志被设置为 1，但路由要求必须分片报文，此报文会被丢弃。这个标志可被用于发往没有能力组装分片的主机。当一个报文被分片，除了最后一片外的所有分片都设置 MF 为 1。最后一个片段具有非零片段偏移字段，将其与未分片数据包区分开，未分片的偏移字段为 0。

- 分片偏移 （Fragment Offset） 这个 13 位字段指明了每个分片相对于原始报文开头的偏移量，以 8 字节作单位。

- 存活时间（Time To Live，TTL） 这个 8 位字段避免报文在互联网中永远存在（例如陷入路由环路）。存活时间以秒为单位，但小于一秒的时间均向上取整到一秒。在现实中，这实际上成了一个跳数计数器：报文经过的每个路由器都将此字段减 1，当此字段等于 0 时，报文不再向下一跳传送并被丢弃，最大值是 255。常规地，一份 ICMP 报文被发回报文发送端说明其发送的报文已被丢弃。这也是 traceroute 的核心原理。

- 协议 （Protocol） 占 8bit，这个字段定义了该报文数据区使用的协议。IANA 维护着一份协议列表（最初由 RFC 790 定义），详细参见 IP 协议号列表。

- 首部检验和 （Header Checksum） 这个 16 位检验和字段只对首部查错，不包括数据部分。在每一跳，路由器都要重新计算出首部检验和并与此字段进行比对，如果不一致，此报文将会被丢弃。重新计算的必要性是因为每一跳的一些首部字段（如 TTL、Flag、Offset 等）都有可能发生变化，不检查数据部分是为了减少工作量。数据区的错误留待上层协议处理——用户数据报协议（UDP）和传输控制协议（TCP）都有检验和字段。此处的检验计算方法不使用 CRC。

- 源地址 一个 IPv4 地址由四个字节共 32 位构成，此字段的值是将每个字节转为二进制并拼在一起所得到的 32 位值。例如，10.9.8.7 是 00001010000010010000100000000111。但请注意，因为 NAT 的存在，这个地址并不总是报文的真实发送端，因此发往此地址的报文会被送往 NAT 设备，并由它被翻译为真实的地址。

- 目的地址 与源地址格式相同，但指出报文的接收端。

- 选项 附加的首部字段可能跟在目的地址之后，但这并不被经常使用，从 1 到 40 个字节不等。请注意首部长度字段必须包括足够的 32 位字来放下所有的选项（包括任何必须的填充以使首部长度能够被 32 位整除）。当选项列表的结尾不是首部的结尾时，EOL（选项列表结束，0x00）选项被插入列表末尾。下表列出了可能。

|字段|长度（位）|描述|
|----|---------|----|
|备份|  1   |当此选项需要被备份到所有分片中时，设为 1。|
| 类 |  2   |常规的选项类别，0 为“控制”，2 为“查错和措施”，1 和 3 保留。|
|数字|  5   |指明一个选项。|
|长度|  8   |指明整个选项的长度，对于简单的选项此字段可能不存在。|
|数据|  可变|选项相关数据，对于简单的选项此字段可能不存在。|

**注：如果首部长度大于 5，那么选项字段必然存在并必须被考虑。 注：备份、类和数字经常被一并称呼为“类型”。**

- 数据 数据字段不是首部的一部分，因此并不被包含在首部检验和中。数据的格式在协议首部字段中被指明，并可以是任意的传输层协议。一些常见协议的协议字段值被列在下面：

|协议字段值|	协议名	|缩写|
|---------|------------|----|
|1	|互联网控制消息协议|ICMP|
|2	|互联网组管理协议  |IGMP|
|6	|传输控制协议	|TCP|
|17	|用户数据报协议	|UDP|
|41	|IPv6 封装	|ENCAP|
|89	|开放式最短路径优先	|OSPF|
|132|流控制传输协议	|SCTP|

## ipv4地址
IPv4 使用 32 位（4 字节）地址，因此地址空间中只有 4,294,967,296（2^32）个地址。不过，一些地址是为特殊用途所保留的，如专用网络（约 1800 万 个地址）和多播地址（约 2.7 亿个地址），这减少了可在互联网上路由的地址数量。随着地址不断被分配给最终用户，IPv4 地址枯竭问题也在随之产生。基于分类网络、无类别域间路由和网络地址转换的地址结构重构显著地减少了地址枯竭的速度。但在 2011 年 2 月 3 日，在最后 5 个地址块被分配给 5 个区域互联网注册管理机构之后，IANA 的主要地址池已经用尽。

IPv4 地址可被写作任何表示一个 32 位整数值的形式，但为了方便人类阅读和分析，它通常被写作点分十进制的形式，即四个字节被分开用十进制写出，中间用点分隔，如 192.168.1.1。ip 地址的编址方法一共经历过三个阶段：

### 分类的 IP 地址
- A 类网络地址占有 1 个字节（8 位），定义最高位为 0 来标识此类网络，余下 7 位为真正的网络地址。后面 3 个字节（24）为主机地址。A 类网络地址第一个字节的十进制值为：001~127.通常用于大型网络。
- B 类网络地址占 2 个字节，使用最高两位为“10”来标识此类地址，其余 14 位为真正的网络地址，主机地址占后面的 2 个字节（16 位）。B 类网络地址第一个字节的十进制值为：128~191.通常用于中型网络。
- C 类网络地址占 3 个字节，它是最通用的 Internet 地址。使用最高三位为“110”来标识此类地址。其余 21 位为真正的网络地址。主机地址占最后 1 个字节。C 类网络地址第一个字节的十进制值为：192~223。通常用于小型网络。
- D 类地址是相当新的。它的识别头是 1110，用于组播，例如用于路由器修改。D 类网络地址第一个字节的十进制值为：224~239。
- E 类地址为实验保留，其识别头是 1111。E 类网络地址第一个字节的十进制值为：240~255。

**但要注意得是，上面得这些地址分类已成为了历史，现在用的都是无分类 IP 地址进行路由选择。**

### 子网的划分

由于上面固定分类的 IP 地址有不少的缺陷，比如，IP 地址空间的利用率很低、固定就意味着不够灵活、使路由表太大而影响性能，为了解决上述的问题，在 IP 地址概念中，又增加了一个“子网字段”，这样的话，一个 IP 地址可以用下面的方式表示

``` sh
IP地址 = (网络号，子网号，主机号)
```

### 无分类编址（CIDR）

为了提高 ip 地址资源的利用率，提出了变长子网掩码（VLSM），而在 VLSM 的研究基础上又提出了“无分类编址”方法，也叫无分类域间路由选择-CIDR。 CIDR 最主要有两个以下特点：

- 消除传统的 A，B，C 地址和划分子网的概念，更有效的分配 IPv4 的地址空间，CIDR 使 IP 地址又回到无分类的两级编码。记法：IP 地址：：={<<网络前缀>，<<主机号>}。CIDR 还使用“斜线记法”即在 IP 地址后面加上“/”然后写网络前缀所占的位数。
- CIDR 把网络前缀都相同的连续 IP 地址组成一个“CIDR 地址块”，即强化路由聚合（构成超网）。 其表示方法

``` sh
IP地址 = (网络前缀，主机号)
```

CIDR 还使用“斜线记法”，在 IP 地址后面加个“/”，紧跟着网络前缀所占的位数。例如：192.168.1.0/24，这种表示方式其实我们在上一章就用了，也是我们最常用的编址方式。

#### CIDR地址的计算方法
CIDR无类域间路由，打破了原本的ABC类地址的规划限定，使用地址段分配更加灵活，日常工作中也经常使用，也正是因为其灵活的特点使我们无法一眼辨认出网络号、广播地址、网络中的第一台主机等信息，本文主要针对这些信息的获得介绍一些计算方法。

当给定一个IP地址，比如18.232.133.86/22，需要求一下这个IP所在网络的 网络地址、子网掩码、广播i地址、这个网络的第一台主机的IP地址：

斜线后是22并不是8的整数倍，直接很难看出结果，所以需要通过一系列的计算。

1. 先用8的整数倍对22进行切割：22 = 16+6 ，所以这个IP地址的前16位保持不动即18.232.

2. 发现问题出在了第三个8位上，这8位中前面6位被拿来做了网络号，后面2位被拿去做了主机号，所以将这8位转化为二进制得到10000101，拿出前6位为<100001>。这是得到了全部的网络号为 18.232.<100001>

3. 将主机号全部置0便是网络地址，18.232.<100001><00>.<00000000>即网络地址为18.232.132.0

4. 同时也得到了这个网络的第一台主机的ip地址，18.232.<100001><00>.<00000001>即18.232.132.1

5. 将主机位全部置1便是广播地址，18.232.<100001><11>.<11111111>即18.232.135.255

6. 子网掩码可以直接使用22计算即可，即前22位都为1，其余为0，即255.255.252.0


| TYPE | CODE | Description | 
| ---- | ---- | ------------|
| 0 | 0 | Echo Reply——回显应答（Ping 应答） 　 | 
| 3 | 0 | Network Unreachable——网络不可达 　 | 
| 3 | 1 | Host Unreachable——主机不可达 　 | 
| 3 | 2 | Protocol Unreachable——协议不可达 　 | 
| 3 | 3 | Port Unreachable——端口不可达 　 | 
| 3 | 4 | Fragmentation needed but no frag. bit set——需要进行分片但设置不分片标志 　 | 
| 3 | 5 | Source routing failed——源站选路失败 　 |
| 3 | 6 | Destination network unknown——目的网络未知 　 | 
| 3 | 7 | Destination host unknown——目的主机未知 　 | 
| 3 | 8 | Source host isolated (obsolete)——源主机被隔离（作废不用） 　 | 
| 3 | 9 | Destination network administratively prohibited——目的网络被强制禁止 　 | 
| 3 | 10 | Destination host administratively prohibited——目的主机被强制禁止 　 | 
| 3 | 11 | Network unreachable for TOS——由于服务类型 TOS，网络不可达 　 | 
| 3 | 12 | Host unreachable for TOS——由于服务类型 TOS，主机不可达 　 | 
| 3 | 13 | Communication administratively prohibited by filtering——由于过滤，通信被强制禁止 　 | 
| 3 | 14 | Host precedence violation——主机越权 　 |
| 3 | 15 | Precedence cutoff in effect——优先中止生效 　 | 
| 4 | 0 | Source quench——源端被关闭（基本流控制） 　 　 | 
| 5 | 0 | Redirect for network——对网络重定向 　 　 | 
| 5 | 1 | Redirect for host——对主机重定向 　 　 | 
| 5 | 2 | Redirect for TOS and network——对服务类型和网络重定向 　 　 | 
| 5 | 3 | Redirect for TOS and host——对服务类型和主机重定向 　 　 | 
| 8 | 0 | Echo request——回显请求（Ping 请求） 　 | 
| 9 | 0 | Router advertisement——路由器通告 　 　 | 
| 10 | 0 | Route solicitation——路由器请求 　 　 | 
| 11 | 0 | TTL equals 0 during transit——传输期间生存时间为 0 　 | 
| 11 | 1 | TTL equals 0 during reassembly——在数据报组装期间生存时间为 0 　 | 
| 12 | 0 | IP header bad (catchall error)——坏的 IP 首部（包括各种差错） 　 | 
| 12 | 1 | Required options missing——缺少必需的选项 　 | 
| 13 | 0 | Timestamp request (obsolete)——时间戳请求（作废不用） 　 | 
| 14 | 　 | Timestamp reply (obsolete)——时间戳应答（作废不用） 　 | 
| 15 | 0 | Information request (obsolete)——信息请求（作废不用） 　 | 
| 16 | 0 | Information reply (obsolete)——信息应答（作废不用） 　 | 
| 17 | 0 | Address mask request——地址掩码请求 　 | 
| 18 | 0 | Address mask | reply——地址掩码应答 |

IP 层最重要的目的是让两个主机之间通信，无论他们相隔多远。IP 协议理论上允许的最大 IP 数据报为 65535 字节（16 位来表示包总长）。但是因为协议栈网络层下面的数据链路层一般允许的帧长远远小于这个值，例如以太网的 MTU 通常在 1500 字节左右。所以较大的 IP 数据包会被分片传递给数据链路层发送，分片的 IP 数据报可能会以不同的路径传输到接收主机，接收主机通过一系列的重组，将其还原为一个完整的 IP 数据报，再提交给上层协议处理。IP 分片会带来一定的问题，分片和重组会消耗发送方、接收方一定的 CPU 等资源，如果存在大量的分片报文的话，可能会造成较为严重的资源消耗；分片丢包导致的重传问题；分片攻击。