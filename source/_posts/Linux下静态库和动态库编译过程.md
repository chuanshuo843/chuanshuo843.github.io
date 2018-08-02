---
title: Linux下静态库和动态库编译过程
author: DuanEnJian
tags:
  - C/C++
  - Linux
categories:
  - 开发
abbrlink: 3393728657
date: 2017-12-27 20:31:00
---
1.动态库
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;动态库又称动态链接库英文为DLL，是Dynamic Link Library 的缩写形式，DLL是一个包含可由多个程序同时使用的代码和数据的库，DLL不是可执行文件。动态链接提供了一种方法，使进程可以调用不属于其可执行代码的函数。函数的可执行代码位于一个 DLL 中，该 DLL 包含一个或多个已被编译、链接并与使用它们的进程分开存储的函数。DLL 还有助于共享数据和资源。多个应用程序可同时访问内存中单个DLL 副本的内容。DLL 是一个包含可由多个程序同时使用的代码和数据的库。Windows下动态库为.dll后缀，在linux在为.so后缀。

2.静态库
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;静态库是指在我们的应用中，有一些公共代码是需要反复使用，就把这些代码编译为“库”文件；在链接步骤中，连接器将从库文件取得所需的代码，复制到生成的可执行文件中的这种库。

<!-- more -->
    
# 目录结构    
>libtest/include/hello.h

```c
#ifdef _HELLO_H_
#define _HELLO_H_

void hello();

#endif
```
>libtest/lib/hello.c

```c
#include "hello.h"
#include <stdio.h>
void hello()
{
	printf("hello world!\n");
}
```
>libtest/src/main.c

```c
#include "hello.h"
int main()
{
	hello();
}
```
# 静态库编译过程
静态库是指在我们的应用中，有一些公共代码是需要反复使用，就把这些代码编译为“库”文件；在链接步骤中，连接器将从库文件取得所需的代码，复制到生成的可执行文件中的这种库。
## 进入libtest/lib目录，执行命令
```bash
gcc -c -I../include hello.c
```
该命令生成目标文件hello.o，注意：参数-I添加头文件搜索目录，这里因为hello.c中有#include “hello.h”，hello.h在libtest/include目录中，这里需要指定该目录通知gcc，否则出现错误提示“找不到头文件 hello.h”。
**这一步将在libtest/lib目录中生成一个hello.o文件。**
## 在libtest/lib目录，执行命令
```bash
ar rc libhello.ahello.o
```
该命令将hello.o添加到静态库文件libhello.a，ar命令就是用来创建、修改库的，也可以从库中提出单个模块，参数r表示在库中插入或者替换模块，c表示创建一个库
**这一步将在libtest/lib目录中生成一个libhello.a文件。**
## 进入libtest/src目录，执行命令
```bash
gcc main.c-I../include -L../lib -lhello -o main
```
该 命令将编译main.c并链接静态库文件libhello.a生成可执行文件main，注意：参数-L添加库文件搜索目录，因为libhello.a在 libtest/lib目录中，这里需要指定该目录通知gcc，参数-l指定链接的库文件名称，名称不用写全名libhello.a，只用写hello即 可。
**这一步将在libtest/src目录中生成可执行文件main。**
## 显示库文件中的索引表
```bash
nm -s libxxx.a
```
# 动态编译库过程
动态库又称动态链接库英文为DLL，是Dynamic Link Library 的缩写形式，DLL是一个包含可由多个程序同时使用的代码和数据的库，DLL不是可执行文件。动态链接提供了一种方法，使进程可以调用不属于其可执行代码的函数。函数的可执行代码位于一个 DLL 中，该 DLL 包含一个或多个已被编译、链接并与使用它们的进程分开存储的函数。DLL 还有助于共享数据和资源。多个应用程序可同时访问内存中单个DLL 副本的内容。DLL 是一个包含可由多个程序同时使用的代码和数据的库。Windows下动态库为.dll后缀，在linux在为.so后缀。

## 进入libtest/lib目录，执行命令
```bash
gcc hello.c-I../include -fPIC -shared -o libhello.so
```
这一步将在当前目录生成动态库文件libhello.so，参数-fPIC -shared固定格式，不用纠结他们什么意思。
## 进入libtest/src目录，执行命令
```bash
gcc main.c-I../include -L../lib -lhello -o main
```
此时在当前目录中已经生成了可执行文件main，执行./main时却提示错误：./main: error while loading shared libraries: libhello.so: cannotopen shared object file: No such file or directory
也就是找不到动态库文件libhello.so，在网上找了答案说如果遇到这样的问题需要设置环境变量LD_LIBRARY_PATH
## 设置环境变量LD_LIBRARY_PATH
```bash
export LD_LIBRARY_PATH="../lib"
gcc main.c -I../include -L../lib -lhello -o main
#然后再执行./main就没有错误了。
```
## 补充
环境变量LD_LIBRARY_PATH指示动态连接器可以装载动态库的路径，在链接动态库文件前设置该变量为库文件所在路径，注意：用export LD_LIBRARY_PATH=”…”方式只是临时生效的，如果要永久有效可以写入~/.bashrc文件中，跟修改PATH类 似，exportLD_LIBRARY_PATH=$LD_LIBRARY_PATH;
当然如果有root权限的话，也可以修改/etc/ld.so.conf文件，将要添加的动态库搜索路径写入该文件中，然后调用/sbin/ldconfig来达到同样的目的。