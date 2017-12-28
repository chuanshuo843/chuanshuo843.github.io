title: PHP之插入排序的实现
author: DuanEnJian
tags:
  - PHP
  - 算法实现
categories:
  - 开发
date: 2017-12-28 16:10:00
---
有一个已经有序的数据序列，要求在这个已经排好的数据序列中插入一个数，但要求插入后此数据序列仍然有序，这个时候就要用到一种新的排序方法——插入排序法,插入排序的基本操作就是将一个数据插入到已经排好序的有序数据中，从而得到一个新的、个数加一的有序数据，算法适用于少量数据的排序，时间复杂度为O(n^2)。是稳定的排序方法。插入算法把要排序的数组分成两部分：第一部分包含了这个数组的所有元素，但将最后一个元素除外（让数组多一个空间才有插入的位置），而第二部分就只包含这一个元素（即待插入元素）。在第一部分排序完成后，再将这个最后元素插入到已排好序的第一部分中。
插入排序的基本思想是：每步将一个待排序的纪录，按其关键码值的大小插入前面已经排序的文件中适当位置上，直到全部插入完为止。

<!-- more -->
# 原理图
{% asset_img 6ab27c0b22dfba06bfff027f0eb4e89399.gif 原理图 %}
# 实现代码
```php
// 插入排序法函数
	function insertion_sort(&$array) {
		$array_length = count($array); // 数组的长度
		
		// 进行数组排序，视第一个数组元素属于一个有序的数组。
		for ($i = 1; $i < $array_length; $i++) {
			$inserted_value = $array[$i]; // 待插入的数组元素
			$inserted_index = $i - 1; // 待插入的位置
			
			// 当$inserted_value前面还有其他数组元素并且值比它小的时候
			while (($inserted_index >= 0) && ($inserted_value < $array[$inserted_index])) {
				$array[$inserted_index + 1] = $array[$inserted_index]; // $inserted_value的前一个数组元素被后移
				$inserted_index--; // 待插入的位置递减变化
			}
			
			// 当$inserted_index的值发生了变化才进行插入操作
			if (($inserted_index + 1) != $i) {
				// 找到了$inserted_value的正确位置，插入该元素。
				$array[$inserted_index + 1] = $inserted_value;
			}
		}
	}
	
	// 数组打印函数
	function print_array($array) {
		foreach ($array as $key => $value) {
			echo "\$array[$key] = $value <br />";
		}
	}
	
	// 初始化数组
	$array = array(1, -1, 3, 3, 2, 9, -10, 7, 6, 5);

	// 调用函数
	insertion_sort($array);
	print_array($array);
	
	/* 输出
	$array[0] = -10 
	$array[1] = -1 
	$array[2] = 1 
	$array[3] = 2 
	$array[4] = 3 
	$array[5] = 3 
	$array[6] = 5 
	$array[7] = 6 
	$array[8] = 7 
	$array[9] = 9
	*/
```