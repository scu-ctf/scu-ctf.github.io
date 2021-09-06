# Web学习路线

# 写在前面

不要把CTF比赛当成你学习的全部，在后面希望学弟学妹们能多看看外面的世界，了解安全圈最新动态找到你最适合的方向

## Web在CTF当中的分类

在CTF比赛中，Web有几大分类：

解题模式：通常是0day挖掘(主要是PHP写的各类CMS的漏洞挖掘)、nday利用(Java、nodejs)；当然传统题型也是有的，主要是Bypass Waf，也就是绕过题目中的限制进行利用

AWD：

早期流行的攻防模式，主要是Web，通常都能直接在网上搜到的nday漏洞，难点在于拿到Webshell后的权限维持

AWD+：

解题与AWD的混合模式，由于AWD模式下选手直接互相干扰情况严重推出的新模式，分为Build与Fix两个阶段，第一阶段就是常规的CTF题目，而第二阶段则对之前的Web题目进行修复

内网渗透：

主要是后渗透，出现在线下比赛当中，首先前台会留给你一个利用点能获得Webshell，接着利用入侵成功的外网服务器作为跳板，攻击内网其他服务器，最后获得敏感数据，并将数据传递到攻击者，看情况安装长期后门，实现长期控制和获得敏感数据的方式

## Web技能栈

你需要知道常见的编程语言：PHP、Java、nodejs、python

单考点主要是：信息泄露、SSTI(服务端模板注入)、XSS(跨站脚本攻击)、Bypass Waf、SQLI(SQL注入)、XXE(XML外部实体)、Unserialize(反序列化攻击)、nday利用、密钥伪造、Xs-leaks攻击等

## 刷题路线

1.[攻防世界](https://adworld.xctf.org.cn/)

- 只需要刷一刷Web新手区即可，学习时需要你百度搜索解法并了解，这个接断主要是培养对Web的基本感觉

2.[CTFHub](https://www.ctfhub.com/)

- 开始进入系统学习截断，注册刷技能树Web分类，涉及信息泄露、密码口令、SQL注入、XSS、XSS、文件上传、RCE、SSRF等

3.[BUUCTF](https://buuoj.cn/)

- 这个时候你已经具备了一定的能力，可以开始学习一些难题了，这时候就是不断拓展难度深入学习的过程

在BUUCTF刷了一段时间后可以尝试报名CTF比赛，彻底开启你的安全之旅

## 详细学习路线

1.首先你需要了解Web安全的一些相关基本概念，通过Google或者Baidu查看Owasp top10攻击利用类型，学会使用github搜索

2.学习常见工具的使用(BurpSuite、sqlmap、dirsearch、AntSword)

- 下载无后门版的这些软件进行安装，百度如Burpsuite的基本使用

3.实战操作，具体可以参考本Wiki当中内容配合Google\Baidu学习

- 了解SQL注入的种类、注入原理、手动注入技巧

- 研究文件上传的原理，如何进行截断、双重后缀欺骗(IIS、PHP)、解析漏洞利用（IIS、Nignix、Apache）等，参照：[上传攻击框架](http://www.owasp.org.cn/OWASP_Training/Upload_Attack_Framework.pdf)；

- 研究XSS形成的原理和种类，可以参考：[XSS](http://www.sec-wiki.com/news/search?wd=XSS)；

- linux与windows常见系统命令，Google\Baidu搜索CTF命令执行与绕过，可以参考：[命令执行绕过](https://blog.csdn.net/solitudi/article/details/109837640?ops_request_misc=%257B%2522request%255Fid%2522%253A%2522163092289416780274180140%2522%252C%2522scm%2522%253A%252220140713.130102334.pc%255Fblog.%2522%257D&request_id=163092289416780274180140&biz_id=0&utm_medium=distribute.pc_search_result.none-task-blog-2~blog~first_rank_v2~rank_v29-1-109837640.pc_v2_rank_blog_default&utm_term=%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C&spm=1018.2226.3001.4450)

- 研究XXE形成的原理和种类，可以参考:[浅谈XXE漏洞原理](https://www.dazhuanlan.com/i9zer/topics/1191073)

4.学习一门脚本编程语言，选择脚本语言Perl/Python/PHP/Go/Java中的一种，对常用库进行编程学习，这在CTF当中将会大大简化我们的利用操作，这里推荐Python，先简简单单看看菜鸟教程并动手学习即可，学习语法、正则、文件、网络、多线程等常用库

5.源码审计与漏洞分析，需要你能独立分析脚本源码程序并发现安全问题

- 熟悉源码审计的动态和静态方法，并知道如何去分析程序，参见[SecWiki-审计](http://www.sec-wiki.com/news/search?wd=审计)；

- 从Wooyun上寻找开源程序的漏洞进行分析并试着自己分析；

- 了解Web漏洞的形成原因，然后通过关键字进行查找分析，参见[SecWiki-代码审计](http://www.sec-wiki.com/news/search?wd=代码审计)、[高级PHP应用程序漏洞审核技术](https://code.google.com/p/pasc2at/wiki/SimplifiedChinese)；

- 研究Web漏洞形成原理和如何从源码层面避免该类漏洞，并整理成checklist。



