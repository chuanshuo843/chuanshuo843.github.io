title: Mysql索引的使用
author: DuanEnJian
tags:
  - MySQL
categories:
  - 数据库
date: 2017-12-27 21:07:00
---
索引是一种特殊的文件(InnoDB数据表上的索引是表空间的一个组成部分)，它们包含着对数据表里所有记录的引用指针。更通俗的说，数据库索引好比是一本书前面的目录，能加快数据库的查询速度。
# 索引类型
索引分为聚簇索引和非聚簇索引两种，聚簇索引是按照数据存放的物理位置为顺序的，而非聚簇索引就不一样了；聚簇索引能提高多行检索的速度，而非聚簇索引对于单行的检索很快。
## 参考资料
[MySQL索引背后的数据结构及算法原理](http://blog.codinglabs.org/articles/theory-of-mysql-index.html)
[MySQL · 引擎特性 · 初识 MySQL GIS 及 InnoDB R-TREE](https://yq.aliyun.com/articles/50625)
[Full-Text Search Functions](http://dev.mysql.com/doc/refman/5.7/en/fulltext-search.html)
[Comparison of B-Tree and Hash Indexes](http://dev.mysql.com/doc/refman/5.7/en/index-btree-hash.html)
[Mysql查看索引使用状态](http://www.ganktools.com/blog/post/backtrack843/Mysql%E6%9F%A5%E7%9C%8B%E7%B4%A2%E5%BC%95%E4%BD%BF%E7%94%A8%E7%8A%B6%E6%80%81)
## B-Tree
最常见的索引类型，基于B-Tree数据结构。B-Tree的基本思想是，所有值（被索引的列）都是排过序的，每个叶节点到跟节点距离相等。所以B-Tree适合用来查找某一范围内的数据，而且可以直接支持数据排序（ORDERBY）。但是当索引多列时，列的顺序特别重要，需要格外注意。InnoDB和MyISAM都支持B-Tree索引。InnoDB用的是一个变种B+Tree，而MyISAM为了节省空间对索引进行了压缩，从而牺牲了性能。
## Hash
基于hash表。所以这种索引只支持精确查找，不支持范围查找，不支持排序。这意味着范围查找或ORDER BY都要依赖server层的额外工作。目前只有Memory引擎支持显式的hash索引（但是它的hash是nonunique的，冲突太多时也会影响查找性能）。Memory引擎默认的索引类型即是Hash索引，虽然它也支持B-Tree索引。
## R-Tree
RTREE在mysql很少使用，仅支持geometry数据类型，支持该类型的存储引擎只有MyISAM、BDb、InnoDb、NDb、Archive几种。相对于BTREE，RTREE的优势在于范围查找。
## Full-text
**MySQL从3.23.23版开始支持全文索引和全文检索**,主要用来查找文本中的关键字，而不是直接与索引中的值相比较。Full-text索引跟其它索引大不相同，它更像是一个搜索引擎，而不是简单的WHERE语句的参数匹配。你可以对某列分别进行full-text索引和B-Tree索引，两者互不冲突。Full-text索引配合MATCH AGAINST操作使用，而不是一般的WHERE语句加LIKE。
# 索引的使用
## 普通索引
```sql
–直接创建索引
CREATE INDEX index_name ON table(column(length))
–修改表结构的方式添加索引
ALTER TABLE table_name ADD INDEX index_name ON (column(length))
–创建表的时候同时创建索引
CREATE TABLE `table` (
`id` int(11) NOT NULL AUTO_INCREMENT ,
`title` char(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`content` text CHARACTER SET utf8 COLLATE utf8_general_ci NULL ,
`time` int(10) NULL DEFAULT NULL ,
PRIMARY KEY (`id`),
INDEX index_name (title(length))
)
–删除索引
DROP INDEX index_name ON table
```
## 唯一索引
```sql
–创建唯一索引
CREATE UNIQUE INDEX indexName ON table(column(length))
–修改表结构
ALTER TABLE table_name ADD UNIQUE indexName ON (column(length))
–创建表的时候直接指定
CREATE TABLE `table` (
`id` int(11) NOT NULL AUTO_INCREMENT ,
`title` char(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`content` text CHARACTER SET utf8 COLLATE utf8_general_ci NULL ,
`time` int(10) NULL DEFAULT NULL ,
PRIMARY KEY (`id`),
UNIQUE indexName (title(length))
);
```
## 全文索引
```sql
–创建表的时候添加全文索引
CREATE TABLE `table` (
`id` int(11) NOT NULL AUTO_INCREMENT ,
`title` char(255) CHARACTER SET utf8 COLLATE utf8_general_ci NOT NULL ,
`content` text CHARACTER SET utf8 COLLATE utf8_general_ci NULL ,
`time` int(10) NULL DEFAULT NULL ,
PRIMARY KEY (`id`),
FULLTEXT (content)
);
–修改表结构添加全文索引
ALTER TABLE article ADD FULLTEXT index_content(content)
–直接创建索引
CREATE FULLTEXT INDEX index_content ON article(content)
```
## 组合索引
```sql
–创建表的时候添加组合索引
CREATE TABLE `test` ('aaa' varchar(16) NOT NULL default '', 'bbb' varchar(16) NOT NULL default '',  'ccc' int(11) UNSIGNED NOT NULL default 0, KEY `sindex` (`aaa`,`bbb`,`ccc`) )  ENGINE=MyISAM COMMENT='';
–修改表结构添加组合索引
ALTER TABLE mytable ADD INDEX name_city_age (name(10),city,age);
```
## 主键索引
```sql
–创建表的时候添加主键索引
CREATE TABLE mytable( ID INT NOT NULL, username VARCHAR(16) NOT NULL, PRIMARY KEY(ID) );
–修改表结构添加主键索引
ALTER TABLE mytable ADD PRIMARY KEY PK_testNoPK(id);
```
# 查看索引信息
```sql
#方法1
show index from k8s_user \G;
#结果:
*************************** 1. row ***************************
        Table: k8s_user
   Non_unique: 0
     Key_name: PRIMARY
 Seq_in_index: 1
  Column_name: id
    Collation: A
  Cardinality: 1
     Sub_part: NULL
       Packed: NULL
         Null: 
   Index_type: BTREE
      Comment: 
Index_comment: 
*************************** 2. row ***************************
        Table: k8s_user
   Non_unique: 0
     Key_name: UserName
 Seq_in_index: 1
  Column_name: username
    Collation: A
  Cardinality: 1
     Sub_part: NULL
       Packed: NULL
         Null: 
   Index_type: BTREE
      Comment: 
Index_comment: 
2 rows in set (0.00 sec)
#方法2
select INDEX_NAME,INDEX_TYPE from INFORMATION_SCHEMA.STATISTICS where TABLE_NAME="k8s_user";
#结果:
+------------+------------+
| INDEX_NAME | INDEX_TYPE |
+------------+------------+
| PRIMARY    | BTREE      |
| UserName   | BTREE      |
+------------+------------+
2 rows in set (0.01 sec)
```