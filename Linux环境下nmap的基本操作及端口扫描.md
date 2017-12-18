#Linux环境下nmap的基本操作及端口扫描
##1.nmap基本操作
> nmap简介

NMap，也就是Network Mapper，最早是Linux下的网络扫描和嗅探工具包。
> 基本功能

1  探测一组主机是否在线
2  扫描主机端口
3  推断主机所用操作系统
> 基本指令

假设所有主机都在192.168.1.0至255上

进行ping扫描，打印出对扫描做出响应的主机,不做进一步测试(如端口扫描或者操作系统探测)：

	nmap -sP 192.168.1.0/24
仅列出指定网络上的每台主机，不发送任何报文到目标主机：

	nmap -sL 192.168.1.0/24
探测目标主机开放的端口，可以指定一个以逗号分隔的端口列表(如-PS22，23，25，80)：

	nmap -PS 192.168.1.234
使用UDP ping探测主机：

	nmap -PU 192.168.1.0/24
使用频率最高的扫描选项：SYN扫描,又称为半开放扫描，它不打开一个完全的TCP连接，执行得很快：

	nmap -sS 192.168.1.0/24
当SYN扫描不能用时，TCP Connect()扫描就是默认的TCP扫描：

	nmap -sT 192.168.1.0/24
UDP扫描用-sU选项,UDP扫描发送空的(没有数据)UDP报头到每个目标端口:

	nmap -sU 192.168.1.0/24
确定目标机支持哪些IP协议 (TCP，ICMP，IGMP等):

	nmap -sO 192.168.1.19
探测目标主机的操作系统：

	nmap -O 192.168.1.19
	nmap -A 192.168.1.19
扫描主机scanme中 所有的保留TCP端口。选项-v启用细节模式。

	nmap -sS -O scanme./24
进行秘密SYN扫描，对象为主机Saznme所在的“C类”网段 的255台主机。同时尝试确定每台工作主机的操作系统类型。因为进行SYN扫描和操作系统检测，这个扫描需要有根权限。

	nmap -sV -p 22，53，110，143，4564 198.116.0-255.1-127
进行主机列举和TCP扫描，对象为B类188.116网段中255个8位子网。这 个测试用于确定系统是否运行了sshd、DNS、imapd或4564端口。如果这些端口打开，将使用版本检测来确定哪种应用在运行。

	nmap -v -iR 100000 -P0 -p 80
随机选择100000台主机扫描是否运行Web服务器(80端口)。由起始阶段 发送探测报文来确定主机是否工作非常浪费时间，而且只需探测主机的一个端口，因此使用-P0禁止对主机列表。

	nmap -P0 -p80 -oX logs/pb-port80scan.xml -oG logs/pb-port80scan.gnmap 216.163.128.20/20
扫描4096个IP地址，查找Web服务器(不ping)，将结果以Grep和XML格式保存。

	host -l | cut -d -f 4 | nmap -v -iL -
进行DNS区域传输，以发现中的主机，然后将IP地址提供给 Nmap。上述命令用于GNU/Linux -- 其它系统进行区域传输时有不同的命令。
其他选项：

		-p (只扫描指定的端口)
单个端口和用连字符表示的端口范 围(如 1-1023)都可以。当既扫描TCP端口又扫描UDP端口时，可以通过在端口号前加上T: 或者U:指定协议。 协议限定符一直有效直到指定另一个。 例如，参数 -p U:53，111，137，T:21-25，80，139，8080 将扫描UDP 端口53，111，和137，同时扫描列出的TCP端口。

		-F (快速 (有限的端口) 扫描)

> nmap常用的端口扫描方式

⑴ TCP同步（SYN）端口扫描（-sS参数）。

它执行得很快，在一个没有入侵防火墙的快速网络上，每秒钟可以扫描数千个 端口。 SYN扫描相对来说不张扬，不易被注意到，因为它从来不完成TCP连接。 它也不像Fin/Null/Xmas，Maimon和Idle扫描依赖于特定平台，而可以应对任何兼容的 TCP协议栈。 它还可以明确可靠地区分open(开放的)， closed(关闭的)，和filtered(被过滤的) 状态
它常常被称为半开放扫描， 因为它不打开一个完全的TCP连接。它发送一个SYN报文， 就像您真的要打开一个连接，然后等待响应。 SYN/ACK表示端口在监听 (开放)，而 RST (复位)表示没有监听者。如果数次重发后仍没响应， 该端口就被标记为被过滤。如果收到ICMP不可到达错误 (类型3，代码1，2，3，9，10，或者13)，该端口也被标记为被过滤。

⑵ TCP connect()端口扫描（-sT参数）。

当SYN扫描不能用时，CP Connect()扫描就是默认的TCP扫描。 当用户没有权限发送原始报文或者扫描IPv6网络时，就是这种情况。 Instead of writing raw packets as most other scan types do，Nmap通过创建connect() 系统调用要求操作系统和目标机以及端口建立连接，而不像其它扫描类型直接发送原始报文。 这是和Web浏览器，P2P客户端以及大多数其它网络应用程序用以建立连接一样的 高层系统调用。它是叫做Berkeley Sockets API编程接口的一部分。Nmap用 该API获得每个连接尝试的状态信息，而不是读取响应的原始报文。

⑶ UDP端口扫描（-sU参数）。

很多流行的服务运行在TCP 协议上，UDP服务也不少。 DNS，SNMP，和DHCP (注册的端口是53，161/162，和67/68)是最常见的三个。 因为UDP扫描一般较慢，比TCP更困难，一些安全审核人员忽略这些端口。
它可以和TCP扫描如 SYN扫描 (-sS)结合使用来同时检查两种协议。

⑷ Ping扫描（-sP参数）。

扫描所在网段上有哪些主机是存活的

> 扫描指令

类型

	 nmap -sT TCP扫描  全链接扫描
	 nmap -sS SYN扫描  半链接扫描
	 nmap -sF FIN扫描  秘密扫描 除SYN、ACK其它位置1
	 nmap -sX Xmas扫描  秘密扫描 FIN、URG、PUSH位置1
	 nmap -sN Null扫描 秘密扫描 标志位全为0，发送TCP分组
	 nmap -sP ping扫描 同时使用ICMP和TCP ACK 80，返回RST说明主机运行(外网)
	 nmap -sU UDP扫描  发送0字节UDP包，快速扫描Windows的UDP端口
	 nmap -sA ACK扫描  TCP ACK扫描，当防火墙开启时，查看防火墙有未过虑某端口
	 nmap -sW 滑动窗口扫描 
	 nmap -sR RPC扫描
	 nmap -b  FTP反弹攻击(FTP Bounce attack) 外网用户通过FTP渗透内网
选项

	 nmap -P0 Nmap扫描前不Ping目标主机
	 nmap -PT Nmap扫描前使用TCP ACK包确定主机是否在运行（-PT默认80）
	 nmap -PS Nmap使用TCP SYN包进行扫描
	 nmap -PI Nmap进行Ping扫描
	 nmap -PB 结合-PT和-PI功能
	 nmap -O  Nmap扫描TCP/IP指纹特征，确定目标主机系统类型
	 nmap -I  反向标志扫描，扫描监听端口的用户
	 nmap -f  分片发送SYN、FIN、Xmas、和Null扫描的数据包
	 nmap -v  冗余模式扫描，可以得到扫描详细信息
	 nmap -oN 扫描结果重定向到文件
	 nmap -resume 使被中断的扫描可以继续
	 nmap -iL -iL,扫描目录文件列表
	 nmap -p  -p扫描端口列表,默认扫描1-1024端口和/usr/share/nmap/nmap-services文件中指定端口；
	    -p例：23；20-30,139,60000-
	 nmap -F  快速扫描模式，只扫描nmap-services文件中的端口
	 nmap -D  欺骗扫描，可有效隐藏扫描者IP地址
	 nmap -S  在欺骗扫描时，用来指定源主机IP
	 nmap -e  指定从哪个网卡发送和接收数据包
	 nmap -g  指定扫描源端口
	 nmap -r  按顺序扫描端口


# 2.端口和端口扫描
> 端口

硬件领域的端口又称接口，如：USB端口、串行端口等。软件领域的端口一般指网络中面向连接服务和无连接服务的通信协议端口，是一种抽象的软件结构，包括一些数据结构和I/O（基本输入输出）缓冲区。

*TCP端口*
TCP：Transmission Control Protocol传输控制协议，TCP是一种面向连接（连接导向）的、可靠的、基于字节流的传输层（Transport layer）通信协议，由IETF的RFC 793说明（specified）。在简化的计算机网络OSI模型中，它完成第四层传输层所指定的功能，UDP是同一层内另一个重要的传输协议。

*UDP端口*
UDP：User Datagram Protocol用户数据报协议，UDP是OSI参考模型中一种无连接的传输层协议，提供面向事务的简单不可靠信息传送服务。UDP 协议基本上是IP协议与上层协议的接口。UDP协议适用端口分别运行在同一台设备上的多个应用程序。

> 端口扫描

端口扫描，顾名思义，就是逐个对一段端口或指定的端口进行扫描。通过扫描结果可以知道一台计算机上都提供了哪些服务，然后就可以通过所提供的这些服务的己知漏洞就可进行攻击。其原理是当一个主机向远端一个服务器的某一个端口提出建立一个连接的请求，如果对方有此项服务，就会应答，如果对方未安装此项服务时，即使你向相应的端口发出请求，对方仍无应答，利用这个原理，如果对所有熟知端口或自己选定的某个范围内的熟知端口分别建立连接，并记录下远端服务器所给予的应答，通过查看一记录就可以知道目标服务器上都安装了哪些服务，这就是端口扫描，通过端口扫描，就可以搜集到很多关于目标主机的各种很有参考价值的信息。例如，对方是否提供FPT服务、WWW服务或其它服务。

> 常用端口号及其对应服务

**windows中**
21端口：21端口主要用于ftp（file transfer protocol，文件传输协议）服务。
23端口：23端口主要用于telnet（远程登录）服务，是internet上普遍采用的登录和仿真程序。
 25端口：25端口为smtp（simple mail transfer protocol，简单邮件传输协议）服务器所开放，主要用于发送邮件，如今绝大多数邮件服务器都使用该协议。
53端口：53端口为dns（domain name server，域名服务器）服务器所开放，主要用于域名解析，dns服务在nt系统中使用的最为广泛。
67、68端口：67、68端口分别是为bootp服务的bootstrap protocol server（引导程序协议服务端）和bootstrap protocol client（引导程序协议客户端）开放的端口。
69端口：tftp是cisco公司开发的一个简单文件传输协议，类似于ftp。 79端口：79端口是为finger服务开放的，主要用于查询远程主机在线用户、操作系统类型以及是否缓冲区溢出等用户的详细信息。
80端口：80端口是为http（hypertext transport protocol，超文本传输协议）开放的，这是上网冲浪使用最多的协议，主要用于在www（world wide web，万维网）服务上传输信息的协议。
109、110端口：109端口是为pop2（post office protocol version 2，邮局协议2）服务开放的，110端口是为pop3（邮件协议3）服务开放的，pop2、pop3都是主要用于接收邮件的。
111端口：111端口是sun公司的rpc（remote procedure call，远程过程调用）服务所开放的端口，主要用于分布式系统中不同计算机的内部进程通信，rpc在多种网络服务中都是很重要的组件。
113端口：113端口主要用于windows的“authentication service”（验证服务）。
 119端口：119端口是为“network news transfer protocol”（网络新闻组传输协议，简称nntp）开放的。
135端口：135端口主要用于使用rpc（remote procedure call，远程过程调用）协议并提供dcom（分布式组件对象模型）服务。
 137端口：137端口主要用于“netbios name service”（netbios名称服务）。
139端口：139端口是为“netbios session service”提供的，主要用于提供windows文件和打印机共享以及unix中的samba服务。
 143端口：143端口主要是用于“internet message access protocol”v2（internet消息访问协议，简称imap）。
 161端口：161端口是用于“simple network management protocol”（简单网络管理协议，简称snmp）。
 443端口：43端口即网页浏览端口，主要是用于https服务，是提供加密和通过安全端口传输的另一种http。
 554端口：554端口默认情况下用于“real time streaming protocol”（实时流协议，简称rtsp）。
1080端口：1080端口是socks代理服务使用的端口，大家平时上网使用的www服务使用的是http协议的代理服务。
 1755端口：1755端口默认情况下用于“microsoft media server”（微软媒体服务器，简称mms）。
 4000端口：4000端口是用于大家经常使用的 聊天工具的，再细说就是为 客户端开放的端口， 服务端使用的端口是8000。
 5554端口：在今年4月30日就报道出现了一种针对微软lsass服务的新蠕虫病毒——震荡波（worm.sasser），该病毒可以利用tcp 5554端口开启一个ftp服务，主要被用于病毒的传播。
 5632端口：5632端口是被大家所熟悉的远程控制软件pcanywhere所开启的端口。
 8080端口：8080端口同80端口，是被用于www代理服务的，可以实现网页端口概念 在网络技术中，端口（port）大致有两种意思：一是物理意义上的端口，比如，adsl modem、集线器、交换机、路由器用于连接其他网络设备的接口，如rj-45端口、sc端口等等。二是逻辑意义上的端口，一般是指tcp/ip协议中的端口，端口号的范围从0到65535，比如用于浏览网页服务的80端口，用于ftp服务的21端口等等。 们这里将要介绍的就是逻辑意义上的端口。

**Linux中**

1 tcpmux TCP 端口服务多路复用 
5 rje 远程作业入口 
7 echo Echo 服务 
9 discard 用于连接测试的空服务 
11 systat 用于列举连接了的端口的系统状态 
13 daytime 给请求主机发送日期和时间 
17 qotd 给连接了的主机发送每日格言 
18 msp 消息发送协议 
19 chargen 字符生成服务；发送无止境的字符流 
20 ftp-data FTP 数据端口 
21 ftp 文件传输协议（FTP）端口；有时被文件服务协议（FSP）使用 
22 ssh 安全 Shell（SSH）服务 
23 telnet Telnet 服务 
25 smtp 简单邮件传输协议（SMTP） 
37 time 时间协议 
39 rlp 资源定位协议 
42 nameserver 互联网名称服务 
43 nicname WHOIS 目录服务 
49 tacacs 用于基于 TCP/IP 验证和访问的终端访问控制器访问控制系统 
50 re-mail-ck 远程邮件检查协议 
53 domain 域名服务（如 BIND） 
63 whois++ WHOIS++，被扩展了的 WHOIS 服务 
67 bootps 引导协议（BOOTP）服务；还被动态主机配置协议（DHCP）服务使用 
68 bootpc Bootstrap（BOOTP）客户；还被动态主机配置协议（DHCP）客户使用 
69 tftp 小文件传输协议（TFTP） 
70 gopher Gopher 互联网文档搜寻和检索 
71 netrjs-1 远程作业服务 
72 netrjs-2 远程作业服务 
73 netrjs-3 远程作业服务 
73 netrjs-4 远程作业服务 
79 finger 用于用户联系信息的 Finger 服务 
80 http 用于万维网（WWW）服务的超文本传输协议（HTTP） 
88 kerberos Kerberos 网络验证系统 
95 supdup Telnet 协议扩展 
101 hostname SRI-NIC 机器上的主机名服务 
102 iso-tsap ISO 开发环境（ISODE）网络应用 
105 csnet-ns 邮箱名称服务器；也被 CSO 名称服务器使用 
107 rtelnet 远程 Telnet 
109 pop2 邮局协议版本2 
110 pop3 邮局协议版本3 
111 sunrpc 用于远程命令执行的远程过程调用（RPC）协议，被网络文件系统（NFS）使用 
113 auth 验证和身份识别协议 
115 sftp 安全文件传输协议（SFTP）服务 
117 uucp-path Unix 到 Unix 复制协议（UUCP）路径服务 
119 nntp 用于 USENET 讨论系统的网络新闻传输协议（NNTP） 
123 ntp 网络时间协议（NTP） 
137 netbios-ns 在红帽企业 Linux 中被 Samba 使用的 NETBIOS 名称服务 
138 netbios-dgm 在红帽企业 Linux 中被 Samba 使用的 NETBIOS 数据报服务 
139 netbios-ssn 在红帽企业 Linux 中被 Samba 使用的NET BIOS 会话服务 
143 imap 互联网消息存取协议（IMAP） 
161 snmp 简单网络管理协议（SNMP） 
162 snmptrap SNMP 的陷阱 
163 cmip-man 通用管理信息协议（CMIP） 
164 cmip-agent 通用管理信息协议（CMIP） 
174 mailq MAILQ 
177 xdmcp X 显示管理器控制协议 
178 nextstep NeXTStep 窗口服务器 
179 bgp 边界网络协议 
191 prospero Cliffod Neuman 的 Prospero 服务 
194 irc 互联网中继聊天（IRC） 
199 smux SNMP UNIX 多路复用 
201 at-rtmp AppleTalk 选路 
202 at-nbp AppleTalk 名称绑定 
204 at-echo AppleTalk echo 服务 
206 at-zis AppleTalk 区块信息 
209 qmtp 快速邮件传输协议（QMTP） 
210 z39.50 NISO Z39.50 数据库 
213 ipx 互联网络分组交换协议（IPX），被 Novell Netware 环境常用的数据报协议 
220 imap3 互联网消息存取协议版本3 
245 link LINK 
347 fatserv Fatmen 服务器 
363 rsvp_tunnel RSVP 隧道 
369 rpc2portmap Coda 文件系统端口映射器 
370 codaauth2 Coda 文件系统验证服务 
372 ulistproc UNIX Listserv 
389 ldap 轻型目录存取协议（LDAP） 
427 svrloc 服务位置协议（SLP） 
434 mobileip-agent 可移互联网协议（IP）代理 
435 mobilip-mn 可移互联网协议（IP）管理器 
443 https 安全超文本传输协议（HTTP） 
444 snpp 小型网络分页协议 
445 microsoft-ds 通过 TCP/IP 的服务器消息块（SMB） 
464 kpasswd Kerberos 口令和钥匙改换服务 
468 photuris Photuris 会话钥匙管理协议 
487 saft 简单不对称文件传输（SAFT）协议 
488 gss-http 用于 HTTP 的通用安全服务（GSS） 
496 pim-rp-disc 用于协议独立的多址传播（PIM）服务的会合点发现（RP-DISC） 
500 isakmp 互联网安全关联和钥匙管理协议（ISAKMP） 
535 iiop 互联网内部对象请求代理协议（IIOP） 
538 gdomap GNUstep 分布式对象映射器（GDOMAP） 
546 dhcpv6-client 动态主机配置协议（DHCP）版本6客户 
547 dhcpv6-server 动态主机配置协议（DHCP）版本6服务 
554 rtsp 实时流播协议（RTSP） 
563 nntps 通过安全套接字层的网络新闻传输协议（NNTPS） 
565 whoami whoami 
587 submission 邮件消息提交代理（MSA） 
610 npmp-local 网络外设管理协议（NPMP）本地 / 分布式排队系统（DQS） 
611 npmp-gui 网络外设管理协议（NPMP）GUI / 分布式排队系统（DQS） 
612 hmmp-ind HMMP 指示 / DQS 
631 ipp 互联网打印协议（IPP） 
636 ldaps 通过安全套接字层的轻型目录访问协议（LDAPS） 
674 acap 应用程序配置存取协议（ACAP） 
694 ha-cluster 用于带有高可用性的群集的心跳服务 
749 kerberos-adm Kerberos 版本5（v5）的“kadmin”数据库管理 
750 kerberos-iv Kerberos 版本4（v4）服务 
765 webster 网络词典 
767 phonebook 网络电话簿 
873 rsync rsync 文件传输服务 

> 查看本机开放的端口

**windows**
以管理员身份运行cmd，输入netstat -ano 即可看到所有连接的PID

**Linux**
使用nmap

	nmap 127.0.0.1