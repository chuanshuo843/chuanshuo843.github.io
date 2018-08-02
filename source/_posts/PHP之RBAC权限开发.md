---
title: PHP之RBAC权限开发
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
abbrlink: 400587758
date: 2017-12-28 16:07:00
---
基于角色的访问控制（Role-Based Access Control）作为传统访问控制（自主访问，强制访问）的有前景的代替受到广泛的关注。在RBAC中，权限与角色相关联，用户通过成为适当角色的成员而得到这些角色的权限。这就极大地简化了权限的管理。在一个组织中，角色是为了完成各种工作而创造，用户则依据它的责任和资格来被指派相应的角色，用户可以很容易地从一个角色被指派到另一个角色。角色可依新的需求和系统的合并而赋予新的权限，而权限也可根据需要而从某角色中回收。角色与角色的关系可以建立起来以囊括更广泛的客观情况。
<!-- more -->
{% asset_img 167f5a1eda6f687af6cdc01d7623802d.png 原理图 %}
# 关于设计
RBAC支持三个著名的安全原则：最小权限原则，责任分离原则，数据抽象原则。
 1. 最小权限原则之所以被RBAC所支持，是因为RBAC可以将其角色配置成其完成任务所需要的最小的权限集。
 2. 责任分离原则可以通过调用相互独立互斥的角色来共同完成敏感的任务而体现，比如要求一个计帐员和财务管理员共参与同一过帐。
 3. 数据抽象可以通过权限的抽象来体现，如财务操作用借款、存款等抽象权限，而不用操作系统提供的典型的读、写、执行权限。然而这些原则必须通过RBAC各部件的详细配置才能得以体现。

# RBAC实现参考ThinkPHP
## 数据库设计
```sql
CREATE TABLE IF NOT EXISTS access` (
  `role_id` smallint(6) unsigned NOT NULL COMMENT '角色ID',
  `node_id` smallint(6) unsigned NOT NULL COMMENT '节点ID',
  `level` tinyint(1) NOT NULL,
  `module` varchar(50) DEFAULT NULL,
  KEY `groupId` (`role_id`),
  KEY `nodeId` (`node_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT '角色节点关联表';

CREATE TABLE IF NOT EXISTS `node` (
  `id` smallint(6) unsigned NOT NULL AUTO_INCREMENT COMMENT '节点ID',
  `name` varchar(20) NOT NULL  COMMENT '节点名称',
  `title` varchar(50) DEFAULT NULL COMMENT '节点中文名',
  `status` tinyint(1) DEFAULT '0' COMMENT '启用状态',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注信息',
  `sort` smallint(6) unsigned DEFAULT NULL COMMENT '排序值',
  `pid` smallint(6) unsigned NOT NULL COMMENT '父节点ID',
  `level` tinyint(1) unsigned NOT NULL COMMENT '节点类型：1:表示应用（模块）；2:表示控制器；3：表示方法',
  PRIMARY KEY (`id`),
  KEY `level` (`level`),
  KEY `pid` (`pid`),
  KEY `status` (`status`),
  KEY `name` (`name`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COMMENT '节点表';

CREATE TABLE IF NOT EXISTS `role` (
  `id` smallint(6) unsigned NOT NULL AUTO_INCREMENT COMMENT '角色ID',
  `name` varchar(20) NOT NULL COMMENT '角色名称',
  `pid` smallint(6) DEFAULT NULL COMMENT '父角色对应ID',
  `status` tinyint(1) unsigned DEFAULT NULL COMMENT '状态',
  `remark` varchar(255) DEFAULT NULL COMMENT '备注',
  PRIMARY KEY (`id`),
  KEY `pid` (`pid`),
  KEY `status` (`status`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COMMENT '角色表' ;

CREATE TABLE IF NOT EXISTS `role_user` (
  `role_id` mediumint(9) unsigned DEFAULT NULL COMMENT '角色ID',
  `user_id` char(32) DEFAULT NULL COMMENT '用户ID',
  KEY `group_id` (`role_id`),
  KEY `user_id` (`user_id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8 COMMENT='角色用户关联表';
```
## 核心实现代码
```php
<?php
namespace Org\Util;
use Think\Db;
/**
 +------------------------------------------------------------------------------
 * 基于角色的数据库方式验证类
 +------------------------------------------------------------------------------
 */
// 配置文件增加设置
// USER_AUTH_ON 是否需要认证
// USER_AUTH_TYPE 认证类型
// USER_AUTH_KEY 认证识别号
// REQUIRE_AUTH_MODULE  需要认证模块
// NOT_AUTH_MODULE 无需认证模块
// USER_AUTH_GATEWAY 认证网关
// RBAC_DB_DSN  数据库连接DSN
// RBAC_ROLE_TABLE 角色表名称
// RBAC_USER_TABLE 用户表名称
// RBAC_ACCESS_TABLE 权限表名称
// RBAC_NODE_TABLE 节点表名称

class Rbac {
    // 认证方法
    static public function authenticate($map,$model='') {
        if(empty($model)) $model =  C('USER_AUTH_MODEL');
        //使用给定的Map进行认证
        return M($model)->where($map)->find();
    }

    //用于检测用户权限的方法,并保存到Session中
    static function saveAccessList($authId=null) {
        if(null===$authId)   $authId = $_SESSION[C('USER_AUTH_KEY')];
        // 如果使用普通权限模式，保存当前用户的访问权限列表
        // 对管理员开发所有权限
        if(C('USER_AUTH_TYPE') !=2 && !$_SESSION[C('ADMIN_AUTH_KEY')] )
            $_SESSION['_ACCESS_LIST']	=	self::getAccessList($authId);
        return ;
    }

	// 取得模块的所属记录访问权限列表 返回有权限的记录ID数组
	static function getRecordAccessList($authId=null,$module='') {
        if(null===$authId)   $authId = $_SESSION[C('USER_AUTH_KEY')];
        if(empty($module))  $module	=	CONTROLLER_NAME;
        //获取权限访问列表
        $accessList = self::getModuleAccessList($authId,$module);
        return $accessList;
	}

    //检查当前操作是否需要认证
    static function checkAccess() {
        //如果项目要求认证，并且当前模块需要认证，则进行权限认证
        if( C('USER_AUTH_ON') ){
			$_module	=	array();
			$_action	=	array();
            if("" != C('REQUIRE_AUTH_MODULE')) {
                //需要认证的模块
                $_module['yes'] = explode(',',strtoupper(C('REQUIRE_AUTH_MODULE')));
            }else {
                //无需认证的模块
                $_module['no'] = explode(',',strtoupper(C('NOT_AUTH_MODULE')));
            }
            //检查当前模块是否需要认证
            if((!empty($_module['no']) && !in_array(strtoupper(CONTROLLER_NAME),$_module['no'])) || (!empty($_module['yes']) && in_array(strtoupper(CONTROLLER_NAME),$_module['yes']))) {
				if("" != C('REQUIRE_AUTH_ACTION')) {
					//需要认证的操作
					$_action['yes'] = explode(',',strtoupper(C('REQUIRE_AUTH_ACTION')));
				}else {
					//无需认证的操作
					$_action['no'] = explode(',',strtoupper(C('NOT_AUTH_ACTION')));
				}
				//检查当前操作是否需要认证
				if((!empty($_action['no']) && !in_array(strtoupper(ACTION_NAME),$_action['no'])) || (!empty($_action['yes']) && in_array(strtoupper(ACTION_NAME),$_action['yes']))) {
					return true;
				}else {
					return false;
				}
            }else {
                return false;
            }
        }
        return false;
    }

	// 登录检查
	static public function checkLogin() {
        //检查当前操作是否需要认证
        if(self::checkAccess()) {
            //检查认证识别号
            if(!$_SESSION[C('USER_AUTH_KEY')]) {
                if(C('GUEST_AUTH_ON')) {
                    // 开启游客授权访问
                    if(!isset($_SESSION['_ACCESS_LIST']))
                        // 保存游客权限
                        self::saveAccessList(C('GUEST_AUTH_ID'));
                }else{
                    // 禁止游客访问跳转到认证网关
                    redirect(PHP_FILE.C('USER_AUTH_GATEWAY'));
                }
            }
        }
        return true;
	}

    //权限认证的过滤器方法
    static public function AccessDecision($appName=MODULE_NAME) {
        //检查是否需要认证
        if(self::checkAccess()) {
            //存在认证识别号，则进行进一步的访问决策
            $accessGuid   =   md5($appName.CONTROLLER_NAME.ACTION_NAME);
            if(empty($_SESSION[C('ADMIN_AUTH_KEY')])) {
                if(C('USER_AUTH_TYPE')==2) {
                    //加强验证和即时验证模式 更加安全 后台权限修改可以即时生效
                    //通过数据库进行访问检查
                    $accessList = self::getAccessList($_SESSION[C('USER_AUTH_KEY')]);
                }else {
                    // 如果是管理员或者当前操作已经认证过，无需再次认证
                    if( $_SESSION[$accessGuid]) {
                        return true;
                    }
                    //登录验证模式，比较登录后保存的权限访问列表
                    $accessList = $_SESSION['_ACCESS_LIST'];
                }
                //判断是否为组件化模式，如果是，验证其全模块名
                if(!isset($accessList[strtoupper($appName)][strtoupper(CONTROLLER_NAME)][strtoupper(ACTION_NAME)])) {
                    $_SESSION[$accessGuid]  =   false;
                    return false;
                }
                else {
                    $_SESSION[$accessGuid]	=	true;
                }
            }else{
                //管理员无需认证
				return true;
			}
        }
        return true;
    }

    /**
     +----------------------------------------------------------
     * 取得当前认证号的所有权限列表
     +----------------------------------------------------------
     * @param integer $authId 用户ID
     +----------------------------------------------------------
     * @access public
     +----------------------------------------------------------
     */
    static public function getAccessList($authId) {
        // Db方式权限数据
        $db     =   Db::getInstance(C('RBAC_DB_DSN'));
        $table = array('role'=>C('RBAC_ROLE_TABLE'),'user'=>C('RBAC_USER_TABLE'),'access'=>C('RBAC_ACCESS_TABLE'),'node'=>C('RBAC_NODE_TABLE'));
        $sql    =   "select node.id,node.name from ".
                    $table['role']." as role,".
                    $table['user']." as user,".
                    $table['access']." as access ,".
                    $table['node']." as node ".
                    "where user.user_id='{$authId}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=1 and node.status=1";
        $apps =   $db->query($sql);
        $access =  array();
        foreach($apps as $key=>$app) {
            $appId	=	$app['id'];
            $appName	 =	 $app['name'];
            // 读取项目的模块权限
            $access[strtoupper($appName)]   =  array();
            $sql    =   "select node.id,node.name from ".
                    $table['role']." as role,".
                    $table['user']." as user,".
                    $table['access']." as access ,".
                    $table['node']." as node ".
                    "where user.user_id='{$authId}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=2 and node.pid={$appId} and node.status=1";
            $modules =   $db->query($sql);
            // 判断是否存在公共模块的权限
            $publicAction  = array();
            foreach($modules as $key=>$module) {
                $moduleId	 =	 $module['id'];
                $moduleName = $module['name'];
                if('PUBLIC'== strtoupper($moduleName)) {
                $sql    =   "select node.id,node.name from ".
                    $table['role']." as role,".
                    $table['user']." as user,".
                    $table['access']." as access ,".
                    $table['node']." as node ".
                    "where user.user_id='{$authId}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=3 and node.pid={$moduleId} and node.status=1";
                    $rs =   $db->query($sql);
                    foreach ($rs as $a){
                        $publicAction[$a['name']]	 =	 $a['id'];
                    }
                    unset($modules[$key]);
                    break;
                }
            }
            // 依次读取模块的操作权限
            foreach($modules as $key=>$module) {
                $moduleId	 =	 $module['id'];
                $moduleName = $module['name'];
                $sql    =   "select node.id,node.name from ".
                    $table['role']." as role,".
                    $table['user']." as user,".
                    $table['access']." as access ,".
                    $table['node']." as node ".
                    "where user.user_id='{$authId}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=3 and node.pid={$moduleId} and node.status=1";
                $rs =   $db->query($sql);
                $action = array();
                foreach ($rs as $a){
                    $action[$a['name']]	 =	 $a['id'];
                }
                // 和公共模块的操作权限合并
                $action += $publicAction;
                $access[strtoupper($appName)][strtoupper($moduleName)]   =  array_change_key_case($action,CASE_UPPER);
            }
        }
        return $access;
    }

	// 读取模块所属的记录访问权限
	static public function getModuleAccessList($authId,$module) {
        // Db方式
        $db     =   Db::getInstance(C('RBAC_DB_DSN'));
        $table = array('role'=>C('RBAC_ROLE_TABLE'),'user'=>C('RBAC_USER_TABLE'),'access'=>C('RBAC_ACCESS_TABLE'));
        $sql    =   "select access.node_id from ".
                    $table['role']." as role,".
                    $table['user']." as user,".
                    $table['access']." as access ".
                    "where user.user_id='{$authId}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and  access.module='{$module}' and access.status=1";
        $rs =   $db->query($sql);
        $access	=	array();
        foreach ($rs as $node){
            $access[]	=	$node['node_id'];
        }
		return $access;
	}
}
```