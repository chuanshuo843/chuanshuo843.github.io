title: PHP的RSA加密解密
tags:
  - PHP
categories:
  - 开发
author: DuanEnJian
date: 2017-12-27 17:45:00
---
php服务端与客户端交互、提供开放api时，通常需要对敏感的部分api数据传输进行数据加密，这时候rsa非对称加密就能派上用处了，下面通过一个例子来说明如何用php来实现数据的加密解密

<!-- more -->

# 生成公钥、私钥
```bash
openssl genrsa -out rsa_private_key.pem 1024
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out private_key.pem
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
```
# PHP进行加密解密
```php
<?php  

/** 
* 密钥文件的路径 
*/  
$privateKeyFilePath = 'rsa_private_key.pem';  
/** 
* 公钥文件的路径 
*/  
$publicKeyFilePath = 'rsa_public_key.pem';  
  
extension_loaded('openssl') or die('php需要openssl扩展支持');  
  
(file_exists($privateKeyFilePath) && file_exists($publicKeyFilePath))  
or die('密钥或者公钥的文件路径不正确');  
/** 
* 生成Resource类型的密钥，如果密钥文件内容被破坏，openssl_pkey_get_private函数返回false 
*/  
$privateKey = openssl_pkey_get_private(file_get_contents($privateKeyFilePath));  
/** 
* 生成Resource类型的公钥，如果公钥文件内容被破坏，openssl_pkey_get_public函数返回false 
*/  
$publicKey = openssl_pkey_get_public(file_get_contents($publicKeyFilePath));  
  
($privateKey && $publicKey) or die('密钥或者公钥不可用');  
/** 
* 原数据 
*/  
$originalData = '我的帐号是:shiki,密码是:matata';  
/** 
* 加密以后的数据，用于在网路上传输 
*/  
$encryptData = '';  
  
echo '原数据为:', $originalData, PHP_EOL;  
  
///////////////////////////////用私钥加密////////////////////////  
if (openssl_private_encrypt($originalData, $encryptData, $privateKey)) {  
  
    /** 
     * 加密后 可以base64_encode后方便在网址中传输 或者打印  否则打印为乱码 
     */  
    echo '加密成功，加密后数据(base64_encode后)为:', base64_encode($encryptData), PHP_EOL;  
  
} else {  
    die('加密失败');  
}  
  
  
///////////////////////////////用公钥解密////////////////////////  
  
/** 
* 解密以后的数据 
*/  
$decryptData ='';  
  
if (openssl_public_decrypt($encryptData, $decryptData, $publicKey)) {  
  
    echo '解密成功，解密后数据为:', $decryptData, PHP_EOL;  
  
} else {  
    die('解密成功');  
}  
```