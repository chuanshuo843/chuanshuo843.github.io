title: Mysql之limit分页数据重复问题
author: o时过境迁心难沉
abbrlink: ec473fdc
tags:
  - MySQL
categories:
  - 开发
date: 2018-10-22 15:38:00
---
在MySQL中我们通常会采用limit来进行翻页查询，比如limit(0,10)表示列出第一页的10条数据，limit(10,10)表示列出第二页。但是，当limit遇到order by的时候，可能会出现翻到第二页的时候，竟然又出现了第一页的记录。

<!-- more -->

# 问题
在MySQL 5.6的版本上，优化器在遇到order by limit语句的时候，做了一个优化，即使用了priority queue。使用 priority queue 的目的，就是在不能使用索引有序性的时候，如果要排序，并且使用了limit n，那么只需要在排序的过程中，保留n条记录即可，这样虽然不能解决所有记录都需要排序的开销，但是只需要 sort buffer 少量的内存就可以完成排序。之所以5.6出现了第二页数据重复的问题，是因为 priority queue 使用了堆排序的排序方法，而堆排序是一个不稳定的排序方法，也就是相同的值可能排序出来的结果和读出来的数据顺序不一致。5.5 没有这个优化，所以也就不会出现这个问题。

# 解决

 给需要排序的字段添加索引（索引本身是有序的，添加索引会按照索引的顺序进行排序返回）
 在排序字段后面再添加一个唯一值的字段排序，比如id（保证参与排序的值不一样就行）
   
# 参考
[8.2.1.17 LIMIT Query Optimization](https://dev.mysql.com/doc/refman/5.7/en/limit-optimization.html)
[Mysql order by与limit混用陷阱](http://wdmcygah.iteye.com/blog/2370591)
[MySQL order by limit 分页数据重复问题](https://juejin.im/post/5af9537bf265da0b9e652dea)
