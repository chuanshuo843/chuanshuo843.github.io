---
title: PHP之二分查找的实现
author: DuanEnJian
tags:
  - PHP
  - 算法实现
categories:
  - 开发
abbrlink: 395626462
date: 2017-12-28 15:48:00
---
二分查找又称折半查找，优点是比较次数少，查找速度快，平均性能好；其缺点是要求待查表为有序表，且插入删除困难。因此，折半查找方法适用于不经常变动而查找频繁的有序列表。首先，假设表中元素是按升序排列，将表中间位置记录的关键字与查找关键字比较，如果两者相等，则查找成功；否则利用中间位置记录将表分成前、后两个子表，如果中间位置记录的关键字大于查找关键字，则进一步查找前一子表，否则进一步查找后一子表。重复以上过程，直到找到满足条件的记录，使查找成功，或直到子表不存在为止，此时查找不成功。
<!-- more -->
# 原理图

{% asset_img 3d7531d4c0f936cda3dc7671ea0389d8.gif 原理图 %}

# 实现代码
```php
<?php
    #二分查找
    function binarySearch(Array $arr, $target) {
        $low = 0;
        $high = count($arr) - 1;
        
        while($low <= $high) {
            $mid = floor(($low + $high) / 2);
            #找到元素
            if($arr[$mid] == $target) return $mid;
            #中元素比目标大,查找左部
            if($arr[$mid] > $target) $high = $mid - 1;
            #重元素比目标小,查找右部
            if($arr[$mid] < $target) $low = $mid + 1;
        }
        
        #查找失败
        return false;
    }
    
    $arr = array(1, 3, 5, 7, 9, 11);
    $inx = binarySearch($arr, 1);
    var_dump($inx);
?>
```