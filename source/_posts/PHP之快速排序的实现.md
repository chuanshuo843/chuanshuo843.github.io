title: PHP之快速排序的实现
author: DuanEnJian
tags:
  - PHP
  - 算法实现
categories:
  - 开发
date: 2017-12-28 16:03:00
---
快速排序（Quicksort）是对冒泡排序的一种改进。
快速排序由C. A. R. Hoare在1962年提出。它的基本思想是：通过一趟排序将要排序的数据分割成独立的两部分，其中一部分的所有数据都比另外一部分的所有数据都要小，然后再按此方法对这两部分数据分别进行快速排序，整个排序过程可以递归进行，以此达到整个数据变成有序序列。
<!-- more -->
# 原理图
{% asset_img 1aa428cc6735892441c0fb1f0aa783c8.gif 原理图 %}
# 实现代码
```php
<?php
function quick_sort($arr){
    //先判断是否需要继续进行
    $length = count($arr);
    if($length <= 1) {
        return $arr;
    }
    //选择第一个元素作为基准
    $base_num = $arr[0];
    //遍历除了标尺外的所有元素，按照大小关系放入两个数组内
    //初始化两个数组
    $left_array = array();  //小于基准的
    $right_array = array();  //大于基准的
    for($i=1; $i<$length; $i++) {
        if($base_num > $arr[$i]) {
            //放入左边数组
            $left_array[] = $arr[$i];
        } else {
            //放入右边
            $right_array[] = $arr[$i];
        }
    }
    //再分别对左边和右边的数组进行相同的排序处理方式递归调用这个函数
    $left_array = quick_sort($left_array);
    $right_array = quick_sort($right_array);
    //合并
    return array_merge($left_array, array($base_num), $right_array);;
}
$arr=array(5,1,0,3,9,10,59,41,78,56,45,47,12,15,45,11);
$rs=quick_sort($arr);
print_r($rs);
//结果
Array
(
    [0] => 0
    [1] => 1
    [2] => 3
    [3] => 5
    [4] => 9
    [5] => 10
    [6] => 11
    [7] => 12
    [8] => 15
    [9] => 41
    [10] => 45
    [11] => 45
    [12] => 47
    [13] => 56
    [14] => 59
    [15] => 78
)
?>
```