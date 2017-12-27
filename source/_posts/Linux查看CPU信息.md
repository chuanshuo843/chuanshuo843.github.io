title: Linux查看CPU信息
author: DuanEnJian
tags:
  - Linux
categories:
  - 运维
date: 2017-12-27 21:48:00
---
# 查看逻辑CPU个数：
```bash
#cat /proc/cpuinfo |grep "processor"|sort -u|wc -l
24
```
# 查看物理CPU个数：
```bash
#grep "physical id" /proc/cpuinfo|sort -u|wc -l     
2
#grep "physical id" /proc/cpuinfo|sort -u             
physical id     : 0
physical id     : 1
``` 
# 查看每个物理CPU内核个数：
```bash
#grep "cpu cores" /proc/cpuinfo|uniq
cpu cores       : 6
```
# 每个物理CPU上逻辑CPU个数：
```bash
#grep "siblings" /proc/cpuinfo|uniq
siblings        : 12
```
# 判断是否开启了超线程：
```
如果多个逻辑CPU的"physical id"和"core id"均相同，说明开启了超线程
或者换句话说
 逻辑CPU个数 > 物理CPU个数 * CPU内核数   开启了超线程
 逻辑CPU个数 = 物理CPU个数 * CPU内核数   没有开启超线程
```
# 查询CPU所有信息:
```bash
#!/bin/bash
 
physicalNumber=0
coreNumber=0
logicalNumber=0
HTNumber=0
 
logicalNumber=$(grep "processor" /proc/cpuinfo|sort -u|wc -l)
physicalNumber=$(grep "physical id" /proc/cpuinfo|sort -u|wc -l)
coreNumber=$(grep "cpu cores" /proc/cpuinfo|uniq|awk -F':' '{print $2}'|xargs)
HTNumber=$((logicalNumber / (physicalNumber * coreNumber)))
 
echo "****** CPU Information ******"
echo "Logical CPU Number  : ${logicalNumber}"
echo "Physical CPU Number : ${physicalNumber}"
echo "CPU Core Number     : ${coreNumber}"
echo "HT Number           : ${HTNumber}"
 
echo "*****************************"
```
执行结果：
```
#./cpuinfo  
****** CPU Information ******
Logical CPU Number  : 24
Physical CPU Number : 2
CPU Core Number     : 6
HT Number           : 2
***************************** 
```

