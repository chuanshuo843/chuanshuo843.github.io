---
title: PHP之冒泡排序的实现
author: DuanEnJian
tags:
  - PHP
  - 算法实现
categories:
  - 开发
abbrlink: 1792372328
date: 2017-12-28 15:58:00
---
冒泡排序（Bubble Sort），是一种计算机科学领域的较简单的排序算法。
它重复地走访过要排序的数列，一次比较两个元素，如果他们的顺序错误就把他们交换过来。走访数列的工作是重复地进行直到没有再需要交换，也就是说该数列已经排序完成。
这个算法的名字由来是因为越大的元素会经由交换慢慢“浮”到数列的顶端，故名。
<!-- more -->
# 原理图
{% asset_img 5b8385253604380494ee9f3453493a9d.gif 原理图 %}
# 实现代码
```php
<?php
/**
 * 冒泡排序算法示例
 */

// 这里以一维数组做演示
$demo_array = array(23,15,43,25,54,2,6,82,11,5,21,32,65);

// 第一层for循环可以理解为从数组中键为0开始循环到最后一个
for ($i=0;$i<count($demo_array);$i++) {
    // 第二层将从键为$i的地方循环到数组最后
    for ($j=$i+1;$j<count($demo_array);$j++) {
        // 比较数组中相邻两个值的大小
        if ($demo_array[$i] > $demo_array[$j]) {
            $tmp            = $demo_array[$i]; // 这里的tmp是临时变量
            $demo_array[$i] = $demo_array[$j]; // 第一次更换位置
            $demo_array[$j] = $tmp;            // 完成位置互换
        }
    }
}

// 打印结果集
echo '<pre>';
var_dump($demo_array);
echo '</pre>';

//结果
array(13) {
  [0] => int(2)
  [1] => int(5)
  [2] => int(6)
  [3] => int(11)
  [4] => int(15)
  [5] => int(21)
  [6] => int(23)
  [7] => int(25)
  [8] => int(32)
  [9] => int(43)
  [10] => int(54)
  [11] => int(65)
  [12] => int(82)
}
```