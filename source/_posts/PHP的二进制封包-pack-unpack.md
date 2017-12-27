title: PHP的二进制封包(pack/unpack)
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 19:57:00
---
通过 TCP/IP 协议传输数据经常会用二进制数据包的形式，在 PHP 中可使用 pack() 和 unpack() 函数进行二进制封包和解包，通过 socket 建立 TCP 连接，并将数据包传输出去。

# 字节序
在不同的计算机体系结构中，对于数据(比特、字节、字)等的存储和传输机制有所不同，因而引发了计算机领域中一个潜在但是又很重要的问题，即通信双方交流的信息单元应该以什么样的顺序进行传送。如果达不成一致的规则，计算机的通信与存储将会无法进行。目前在各种体系的计算机中通常采用的字节存储机制主要有两种：大端(Big-endian)和小端(Little-endian)。这里所说的大端和小端即是字节序。**网络字节序是指大端序。TCP/IP都是采用网络字节序的方式**

```php
<?php
function IsBigEndian(){
	$bin = pack("L", 0x12345678);
	$hex = bin2hex($bin);
	if (ord(pack("H2", $hex)) === 0x78){
		return FALSE;
	}
	return TRUE;
}

if (IsBigEndian()){
	echo "大端序";
}else{
	echo "小端序";
}

//测试
//php -f pack.php
//小端序
```
# Pack参数说明
| Code          | Description           |
| ------------- |:-------------:|
| a             | 将字符串空白以 NULL 字符填满| 
| A             | 将字符串空白以 SPACE 字符 (空格) 填满|
| h             | 16进制字符串，低位在前以半字节为单位|
| H             | 16进制字符串，高位在前以半字节为单位|
| c             | 有符号字符|
| C             | 无符号字符|
| s             | 有符号短整数 (16位，主机字节序)|
| S             | 无符号短整数 (16位，主机字节序)|
| n             | 无符号短整数 (16位, 大端字节序)|
| v             | 无符号短整数 (16位, 小端字节序)|
| i             | 有符号整数 (依赖机器大小及字节序)|
| I             | 无符号整数 (依赖机器大小及字节序)|
| l             | 有符号长整数 (32位，主机字节序)|
| L             | 无符号长整数 (32位，主机字节序)|
| N             | 无符号长整数 (32位, 大端字节序)|
| V             | 无符号长整数 (32位, 小端字节序)|
| f             | 单精度浮点数 (依计算机的范围)|
| d             | 双精度浮点数 (依计算机的范围)|
| x             | 空字节|
| X             | 倒回一位|
| @             | 填入 NULL 字符到绝对位置|
# 使用例子
比如现在要通过PHP发送数据包到服务器来登录。在仅需要提供用户名(最多30个字节)和密码(md5之后固定为32字节)的情况下，可以构造如下数据包(当然这事先需要跟服务器协商好数据包的规范，本例以网络字节序通信)

## 包结构
|字段           |字节数         |说明|
| ------------- |:-------------:|-------------:|
|包头           |定长	        |每一个通信消息必须包含的内容|
|包体	        |不定长	        |根据每个通信消息的不同产生变化|
## 包头详细内容
|字段           |字节数         |类型          |说明          |            
| ------------- |:-------------:|-------------:|-------------:|
|pkg_len        |2              | ushort       |整个包的长度，不超过4K|
|version	    |1	            |uchar	       |通讯协议版本号|
|command_id	    |2	            |ushort	       |消息命令ID|
|result	        |2	            |short	       |请求时不起作用；请求返回时使用|
## Pack打包
包头是定长的，通过计算可知包头占7个字节，并且包头在包体之前。比如用户test需要登录，密码是123456

```php
<?php
$version    = 1; //协议版本
$result     = 0; 
$command_id = 1001; //消息ID
$username   = "test"; //用户账号
$password   = md5("123456"); //用户密码
// 构造包体
$bin_body   = pack("a30a32", $username, $password);
// 包体长度
$body_len   = strlen($bin_body);
$bin_head   = pack("nCns", $body_len, $version, $command_id, $result);
$bin_data   = $bin_head . $bin_body;
// 发送数据
socket_write($socket, $bin_data, strlen($bin_data));
socket_close($socket);
```
以上的代码中，pack("a30a32", $username, $password);a30表示30个a，您当然可以连续写30个a，但我想您不会这么傻。如果是a*的话，则表示任意多个a。通过服务器端的输出来看，PHP发送了30个字节过去，服务器端也接收了30个字节，但因为填充的\0是空字符，所以您不会看到有什么不一样的地方,a32同理

## unpack解包
unpack是用来解包经过pack打包的数据包，如果成功，则返回数组。其中格式化字符和执行pack时一一对应，但是需要额外的指定一个key，用作返回数组的key。多个字段用/分隔。

```php
<?php
$bin = @pack("a9SS", "test", 20, 1);
$data = @unpack("a9name/sage/Sgender", $bin);

if (is_array($data))
{
	print_r($data);
}


//测试
$ php  -f pack.php
Array
(
    [name] => test
    [age] => 20
    [gender] => 1
)
```
# 参考文章
[PHP: 深入pack/unpack](https://my.oschina.net/goal/blog/195749)
[PHP: chr和pack、unpack那些事](https://my.oschina.net/goal/blog/202378)
[PHP: pack/unpack补遗](https://my.oschina.net/goal/blog/202381)