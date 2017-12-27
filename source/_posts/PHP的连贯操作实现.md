title: PHP的连贯操作实现
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:56:00
---
编程语言中的链式操作是利用运算符进行的连续运算（操作），它的特点是在一条语句中出现两个或者两个以上相同的操作符，如连续的赋值操作、连续的输入操作、连续的输出操作、连续的相加操作等都是链式操作的例子。
# 核心实现类
```php
<?php
    //数据库操作基类[PS:主要功能连贯功能实现]
    class Db{
        //此属性定义要实现连贯操作的方法名
        public $sql = array(
            "field" => "",
            "where" => "",
            "order" => "",
            "limit" => "",
            "group" => "",
            "having" => "",
        );

        /**
         * 连贯操作时,调用field() where() order() limit() group() having()方法且组合成sql语句
         * 此方法为PHP魔术方法,调用类中不存在的方法时就会自动调用此方法
         * @param $methodName 调用不存在的方法时,接收这个方法名称的字符串
         * @param $args 调用不存在的方法时,接收这个方法的参数,以数组形式接收
         */
        function __call($methodName,$args){
            //把要请求的方法名,统一转为小写
            $methodName=strtolower($methodName);
            //若请求方法名与成员属性数组$sql下标对应上;则将第二个参数,赋值给数组中"下标对应的元素"
            if(isset($this->sql[$methodName])){
                $this->sql[$methodName]=$args[0];
            }else{
                echo '调用类'.get_class($this).'中的'.$methodName.'()方法不存在';
            }
            //返回对象;从而可以继续调用本对象中的方法,形成连贯操作
            return $this;
        }

        /**
         * 用此方法拼接成一个select的sql语句;[PS:此方法终结了连贯操作,置于连贯操作的最后面]
         */
        function select(){
            //按照select语法拼接sql字符串[PS:可以在mysql命令行中执行"help select;"查看其语法构结]
            $sql="SELECT {$this->sql['field']} FROM test {$this->sql['where']} {$this->sql['group']}{$this->sql['having']} {$this->sql['order']} {$this->sql['limit']}";
            echo $sql;
        }
    }
```
# 调用方式
```
    $obj=new db();
    $obj->field('name,sex,address')->where('where name="gongwen"')->limit('limit 1')->select();
    //输出:SELECT name,sex,address FROM test where name=gongwen limit 1
```