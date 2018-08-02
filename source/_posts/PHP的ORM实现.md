---
title: PHP的ORM实现
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
abbrlink: 4014080582
date: 2017-12-27 20:15:00
---
对象关系映射（英语：Object Relation Mapping，简称ORM，或O/RM，或O/R mapping），是一种程序技术，用于实现面向对象编程语言里不同类型系统的数据之间的转换。从效果上说，它其实是创建了一个可在编程语言里使用的“虚拟对象数据库”。

<!-- more -->
# ORM说明
一般的ORM包括以下四部分

- 一个对持久类对象进行CRUD操作的API；
- 一个语言或API用来规定与类和类属性相关的查询；
- 一个规定MAPPING METADATA的工具；
- 一种技术可以让ORM的实现同事务对象一起进行DIRTYCHECKING, LAZY ASSOCIATION FETCHING以及其他的优化操作。

# 代码参考
-----
## 核心实现类
```php
<?php
abstract class Model{
   protected $pk = 'id';
   protected $_ID = null; 
   protected $_tableName;
   protected $_arRelationMap;
   protected $_modifyMap;
   protected $is_load = false;
   protected $_blForDeletion;
   protected $_DB;

   public function __consturct($id = null){
       $this->_DB = mysql_connect('127.0.0.1','root','') ;
       $this->_tableName = $this->getTableName();
       $this->_arRelationMap = $this->getRelationMap();
       if(isset($id))$this->_ID = $id;
   }
   abstract protected function getTableName();
   abstract protected function getRelationMap();

   public function Load(){
       if(isset($this->_ID)){
           $sql = "SELECT ";
           foreach($this->_arRelationMap as $k => $v){
               $sql .= '`'.$k.'`,';
           }
           $sql .= substr($sql,0,strlen($sql)-1);
           $sql .= "FROM ".$this->_tableName." WHERE ".$this->pk." = ".$this->_ID;
           $result =$this->_DB->mysql_query($sql);
           foreach($result[0] as $k1 => $v1){
              $member = $this->_arRelationMap[$key];
              if(property_exists($this,$member)){
                 if(is_numeric($member)){
                     eval('$this->'.$member.' = '.$value.';');
                 }else{
                     eval('$this->'.$member.' = "'.$value.'";');
                 }
              }
           }
       }
       $this->is_load = true;
   }
   public function __call($method,$param){
      $type   = substr($method,0,3);
      $member = substr($method,3);
      switch($type){
         case 'get':
             return $this->getMember($member);
             break;
         case 'set':
             return $this->setMember($member,$param[0]);
      }
      return false;
   }
   public function setMember($key){
       if(property_exists($this,$key)){
          if(is_numeric($val)){
             eval('$this->'.$key.' = '.$val.';');
          }else{
             eval('$this->'.$key.' = "'.$val.'";');
          }
          $this->_modifyMap[$key] = 1;
       }else{
          return false;
       }
   }
   
   public function getMember($key,$val){
       if(!$this->is_load){
          $this->Load();
       }
       if(property_exists($this,$key)){
          eval('$res = $this->'.$key.';' );
          return $this->$key;
       }
       return false;
   }

   public function save(){
      if(isset($this->_ID)){
          $sql = "UPDATE ".$this->_tableName." SET ";
          foreach($this->arRelationMap as $k2 => $v2){
              if(array_key_exists( $k2, $this->_modifyMap)){
                  eval( '$val = $this->'.$v2.';');
                  $sql_update .=  $v2." = ".$val;
              }
          }
          $sql .= substr($sql_update,0,strlen($sql_update));
          $sql .= 'WHERE '.$this->pk.' = '.$this->_ID;
      }else{
          $sql = "INSERT INTO ".$this->_tableName." (";
          foreach($this->arRelationMap as $k3 => $v3){
              if(array_key_exists( $k3,$this->_modifyMap)){
                  eval('$val = $this->'.$v3.';');
                  $field  .= "`".$v3."`,"; 
                  $values .= $val;
              }
          }
          $fields = substr($field,0,strlen($field)-1);
          $vals   = substr($values,0,strlen($values)-1);
          $sql .= $fields." ) VALUES (".$vals.")";
      }
      echo $sql;
      //$this->_DB->query($sql);
   }
   public function __destory(){
      if(isset($this->ID)){
         $sql = "DELETE FROM ".$this->_tableName." WHERE ".$this->pk." = ".$this->_ID;
        // $this->_DB_query($sql);
      }
   }
}
```
## 具体实现
```php
<?php
class User extends Model{
    protected  function getTableName(){
       return "test_user";
    }
    protected function getRelationMap(){
        return array( 
                      'id'       => USER_ID,
                      'user_name'=> USER_NAME,
                      'user_age' => USER_AGE
                    );
    }
    public function getDB(){
       return $this->_DB;
    }
}
```
## 调用方式
```php
<?php
$UserIns = new User();
print_r($UserIns);

```