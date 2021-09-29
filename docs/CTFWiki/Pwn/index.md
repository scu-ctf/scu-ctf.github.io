# CTF PWN 入门 

By [jkilopu](http://jkblog.site/)

## 写在前面

本文中的观点都只是个人的经验之谈，ctf pwn 不止这些，二进制安全也远不止这些。

## 简介

PWN = 理解目标工作原理 + 漏洞挖掘 + 漏洞利用

CTF 中的 pwn 题，目前最基本、最经典的就是 Linux 下的用户态程序的漏洞挖掘和利用。

其中的典中典就是栈题和堆题了，可以说是每个 pwn 选手的必经之路，但也不要花太长时间在一些奇奇怪怪的技巧上，对之后的学习帮助不大。

## 前置技能

在真正做出并理解一个 pwn 题前，你可能需要的技能：

1. 了解基本的 Linux 命令

2. 能编写基本的 C 语言代码

3. 调试能力

   会用 gdb 或 ida remote debugger 调试 linux 下的程序

4. 基本的逆向能力

   通常来说，pwn 题只会给编译好的二进制程序。需要通过逆向搞清程序的逻辑。

5. 能用 python 编写简单的脚本

   在 ctf 中，编写 exp（漏洞利用脚本）时一般都会用到 [pwntools](https://github.com/Gallopsled/pwntools) 框架。

6. __上网

7. 热情与耐心

## 推荐书籍

接下来介绍的书籍对理解计算机底层比较有帮助，能让你在 pwn 时知其然也知其所以然。

1. 《CSAPP》，中文名称《深入理解计算机系统》（其实直译应该是《计算机系统：从程序员的角度》）：学习 x86_64 汇编，重点看第 4 章程序的机器级表示。推荐做一下配套课程中的两个 [lab](http://csapp.cs.cmu.edu/3e/labs.html)：bomb 和 attack，学习简单逆向和栈溢出（好像还有基本的 ROP？我记不清了）。这两个 lab 很有意思。
2. 《程序员的自我修养——链接、装载与库》 ：介绍了 C 源代码如何经过一系列的操作最终变为二进制程序。
3. 《x86 汇编语言：从实模式到保护模式》：介绍了更加贴近底层、跟操作系统相关的汇编，以及一些 x86 CPU、操作系统的工作原理。初学时不需要看。

## 推荐资源

### 教程类

1. [ctf-wiki](https://ctf-wiki.org/)：涵盖了大部分 ctf pwn 题的漏洞利用方法，而且配有题目讲解。强烈推荐。
2. [how2heap](https://github.com/shellphish/how2heap)：教你各个版本下的 glibc ptmalloc2 堆利用方法。

### 刷题类

1. [攻防世界](https://adworld.xctf.org.cn/task)：有很多适合新手的题
2. [buuoj](https://buuoj.cn/)：有大量比赛题。这个平台还会每月举办月赛，可以关注一下。

### 比赛类

1. [ctftime](https://ctftime.org/)：国际的高质量赛事
2. [ctfhub](https://www.ctfhub.com/#/calendar)：国内外赛事，可以订阅一下日历

### 工具类

1. [pwntools](https://github.com/Gallopsled/pwntools)：可能是用的人最多的 ctf pwn 框架，用它写 exp 十分方便（虽然我也没试过 [zio](https://github.com/zTrix/zio) 啥的）
2. ida：没有 ida 的 F5 我就走不动路
3. [pwndbg](https://github.com/pwndbg/pwndbg)：可能是 ctf pwn 中最好用的 gdb 插件，还支持一些异架构（mips、arm 等）以及 qemu 的调试
4. [patchelf](https://github.com/NixOS/patchelf)：一般用来改变 elf 文件的动态链接库和动态链接器。很常用。
5. [libc rip](https://libc.rip/)：当你泄漏了 glibc 中的地址却没有 glibc 动态链接库时，通过符号和地址中的低 24 bit 有可能找到对应的 glibc（glibc 安息吧，你被打得够惨了）
6. [LibcSearcher](https://github.com/lieanu/LibcSearcher)：一个 python 库，功能同上。但里面的 [libc-database](https://github.com/niklasb/libc-database) 有点老了，需要更新一下。
7. [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one)：我主要用它下载含 debug symbol 的 glibc，这样方便查看堆相关的一些信息。
8. [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)：以前我用它找 gadget，现在我一般用 ropper
9. [Ropper](https://github.com/sashs/Ropper)：寻找速度似乎比 ROPgadget 快一些
10. [one_gadget](https://github.com/david942j/one_gadget)：覆盖跳转地址然后一把梭
11. [seccomp-tools](https://github.com/david942j/seccomp-tools)：分析 seccomp 沙盒

## 更多的 ctf pwn

除了典中典之栈题和堆题外，现在一些质量比较高的题考察的知识面更广，还会涉及和实战相关的一些知识。

下面介绍的有些东西我接触得比较少，描述可能不够精确和全面。

### 虚拟机

程序实现了一套自定义的指令集，并用软件模拟的方式解析指令。

要么找指令实现的漏洞，要么找跑在该指令集下的程序的漏洞。

逆向量比较大。

### 更多的逆向

把 reverse 中的一些内容融入到 pwn 题中，有融得好的也有不好的。

### 密码学

把 crypto 中的一些内容融入到 pwn 题中。

### 更多的 malloc

tcmalloc、musl libc 中的 malloc

### 异架构

arm、mips、risc-v...同一份 C 源代码，在不同架构上的漏洞点和利用方法可能大相径庭。

有时候还会出一些非常冷门的架构，工具都很难找。这时就需要自己动手了。

### C++ 及其它语言

一些高级语言的特性反编译的结果会比较难懂

### Linux kernel pwn

linux .ko 驱动的漏洞挖掘和利用。

### windows pwn

### web pwn

前几天长安杯看见一个 nodejs，完全不会。

## 实战

以下的东西我都没实际接触过，所以就当我在报菜名吧。

也许我以后学了其中的一点点后会补充内容。

### 物联网

### 内核

### 浏览器

### 虚拟化

### fuzz

## 其它

[0x401 官网](https://www.0x401.com/)

[scuctf](https://www.scuctf.com)

[So you want to work in security?](http://ifsec.blogspot.com/2018/02/so-you-want-to-work-in-security-and-for.html) 

[我的 github](https://github.com/jkilopu)

我的邮箱：jkilopu8@gmail.com

我的 qq（欢迎私聊，加好友时请说明来意）：2139136172

