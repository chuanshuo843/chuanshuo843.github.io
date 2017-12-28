title: PHP实现ACL权限控制
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:18:00
---
ACL是存在于计算机中的一张表，它使操作系统明白每个用户对特定系统对象，例如文件目录或单个文件的存取权限。每个对象拥有一个在访问控制表中定义的安全属性。这张表对于每个系统用户有拥有一个访问权限。最一般的访问权限包括读文件（包括所有目录中的文件），写一个或多个文件和执行一个文件（如果它是一个可执行文件或者是程序的时候）。Windows NT，Novell公司的Netware，Digital公司的 OpenVMS和基于UNIX系统是使用这种访问控制表的系统。而此表的实现在各个系统中却不一样。 

在Windows NT中，每个系统对象和一个访问控制表相关。每个ACL都有一个或多个访问控制入口，包括用户名或用户组的名称。对于每个用户，组或人物，他们的访问权限在表中的一个位串中记录。一般说来，系统管理员和对象的所有者创建对象的访问控制表。 

<!-- more -->
# 数据库结构
```sql
-- ACL Tables
-- 表的结构 `aclresources`
DROP TABLE IF EXISTS `aclresources`;
CREATE TABLE IF NOT EXISTS `aclresources` (
`rsid` varchar(64) NOT NULL ,
`access` int(4) NOT NULL default 0,
`desc` varchar(240) NOT NULL default '',
`created_at` int(10) unsigned NOT NULL default 1,
`updated_at` int(10) unsigned NOT NULL default 0,
PRIMARY KEY (`rsid`)
)DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
-- 表的结构 `aclroles`
DROP TABLE IF EXISTS `aclroles`;
CREATE TABLE IF NOT EXISTS `aclroles` (
`id` int(10) unsigned NOT NULL auto_increment,
`rolename` varchar(32) NOT NULL ,
`desc` varchar(240) NOT NULL default '',
`created_at` int(10) unsigned NOT NULL default 1,
`updated_at` int(10) unsigned NOT NULL default 0,
PRIMARY KEY (`id`),
UNIQUE KEY `rolename` (`rolename`)
)DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
-- 表的结构 `ref_aclresources_aclroles`
DROP TABLE IF EXISTS `ref_aclresources_aclroles`;
CREATE TABLE IF NOT EXISTS `ref_aclresources_aclroles` (
`rsid` varchar(64) NOT NULL ,
`role_id` int(10) unsigned NOT NULL ,
PRIMARY KEY (`rsid`,`role_id`)
)DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
-- 表的结构 `ref_users_aclroles`
DROP TABLE IF EXISTS `ref_users_aclroles`;
CREATE TABLE IF NOT EXISTS `ref_users_aclroles` (
`user_id` int(10) unsigned NOT NULL auto_increment,
`role_id` int(10) unsigned NOT NULL ,
PRIMARY KEY (`user_id`,`role_id`)
)DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
-- 表的结构 `users`
DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
`id` int(10) unsigned NOT NULL auto_increment,
`email` varchar(128) NOT NULL,
`password` varchar(64) NOT NULL,
`nickname` varchar(32) NOT NULL default '',
`roles` varchar(240) NOT NULL default '',
`created_at` int(10) unsigned NOT NULL default 1,
`updated_at` int(10) unsigned NOT NULL default 0,
PRIMARY KEY (`id`),
UNIQUE KEY `user_email` (`email`)
)DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
```
# 核心实现代码
```php
<?php
/**
* 简单的 ACL 权限控制功能
*
* 表定义
*
* 1. 资源定义 (rsid,access,desc,created_at,updated_at)
* 2. 角色定义 (id,rolename,desc,created_at,updated_at)
* 3. 资源-角色关联 (rsid,role_id)
* 4. 用户-角色关联 (user_id,role_id)
*
* 依赖db.php sqlobject.php
*
*/
class AclBase {
// --- ACL 访问授权 

/**
* 不允许任何人访问
*/
const NOBODY = 0; 

/**
* 允许任何人访问
*/
const EVERYONE = 1; 

/**
* 允许 拥有角色的用户访问
*/
const HAS_ROLE = 2; 

/**
* 允许 不带有角色的用户访问
*/
const NO_ROLE = 3;
/**
* 在 资源-角色关联 定义的 角色才能访问
*/
const ALLOCATE_ROLES = 4; 

// 定义相关的 表名
public $tbResources = 'aclresources';
public $tbRoles = 'aclroles';
public $tbRefResourcesRoles = 'ref_aclresources_aclroles';
public $tbRefUsersRoles = 'ref_users_aclroles'; 

/**
* 格式化 资源的访问权限并返回
*
* @return int
*/
static function formatAccessValue($access){
static $arr = array(self::NOBODY,self::EVERYONE,self::HAS_ROLE,self::NO_ROLE,self::ALLOCATE_ROLES);
return in_array($access,$arr) ? $access : self::NOBODY;
} 

/**
* 创建资源,返回资源记录主键
*
* @param string $rsid
* @param int $access
* @param string $desc
*
* @return int
*/
function createResource($rsid,$access,$desc){
if (empty($rsid)) return false; 

$resource = array(
'rsid' => $rsid,
'access' => self::formatAccessValue($access),
'desc' => $desc,
'created_at' => CURRENT_TIMESTAMP
); 

return SingleTableCRUD::insert($this->tbResources,$resource);
} 

/**
* 修改资源,返回成功状态
*
* @param array $resource
* @return int
*/
function updateResource(array $resource){
if (!isset($resource['rsid'])) return false; 

$resource['updated_at'] = CURRENT_TIMESTAMP; 

return SingleTableCRUD::update($this->tbResources,$resource,'rsid');
} 

/**
* 删除资源
*
* @param string $rsid
* @return int
*/
function deleteResource($rsid){
if (empty($rsid)) return false;
return SingleTableCRUD::delete($this->tbResources,array('rsid'=>$rsid));
} 

/**
* 创建角色,返回角色记录主键
*
* @param string $rolename
* @param string $desc
*
* @return int
*/
function createRole($rolename,$desc){
if (empty($rolename)) return false; 

$role = array(
'rolename' => $rolename,
'desc' => $desc,
'created_at' => CURRENT_TIMESTAMP
); 

return SingleTableCRUD::insert($this->tbRoles,$role);
} 

/**
* 修改角色,返回成功状态
*
* @param array $role
* @return int
*/
function updateRole(array $role){
if (!isset($role['id'])) return false; 

if (isset($role['rolename'])) unset($role['rolename']);
$role['updated_at'] = CURRENT_TIMESTAMP; 

return SingleTableCRUD::update($this->tbRoles,$role,'id');
} 

/**
* 删除角色
*
* @param int $role_id
* @return int
*/
function deleteRole($role_id){
if (empty($role_id)) return false;
return SingleTableCRUD::delete($this->tbRoles,array('role_id'=>(int) $role_id));
} 

/**
* 为资源指定角色,每次均先全部移除表中相关记录再插入
*
* @param int $rsid
* @param mixed $roleIds
* @param boolean $setNull 当角色id不存在时,是否将资源从关联表中清空
*/
function allocateRolesForResource($rsid,$roleIds,$setNull=false,$defaultAccess=-1){
if (empty($rsid)) return false; 

$roleIds = normalize($roleIds,',');
if (empty($roleIds)){
if ($setNull){
SingleTableCRUD::delete($this->tbRefResourcesRoles,array('rsid'=>$rsid)); 

if ($defaultAccess != -1){
$defaultAccess = self::formatAccessValue($defaultAccess);
$this->updateResource(array('rsid'=>$rsid,'access'=>$defaultAccess));
}
return true;
}
return false;
} 

SingleTableCRUD::delete($this->tbRefResourcesRoles,array('rsid'=>$rsid)); 

$roleIds = array_unique($roleIds); 

foreach ($roleIds as $role_id){
SingleTableCRUD::insert($this->tbRefResourcesRoles,array('rsid'=>$rsid,'role_id'=>(int)$role_id));
}
return true;
} 

function cleanRolesForResource($rsid){
if (empty($rsid)) return false;
return SingleTableCRUD::delete($this->tbRefResourcesRoles,array('rsid'=>$rsid));
} 

function cleanResourcesForRole($role_id){
if (empty($role_id)) return false;
return SingleTableCRUD::delete($this->tbRefResourcesRoles,array('role_id'=>(int) $role_id));
} 

/**
* 为角色分配资源,每次均先全部移除表中相关记录再插入
*
* @param int $role_id
* @param mixed $rsids
*
* @return boolean
*/
function allocateResourcesForRole($role_id,$rsids){
if (empty($role_id)) return false; 

$role_id = (int) $role_id;
$rsids = normalize($rsids,',');
if (empty($rsids)){
return false;
} 

SingleTableCRUD::delete($this->tbRefResourcesRoles,array('role_id'=>$role_id)); 

$rsids = array_unique($rsids); 

foreach ($rsids as $rsid){
SingleTableCRUD::insert($this->tbRefResourcesRoles,array('rsid'=>$rsid,'role_id'=>$role_id));
}
return true;
} 

/**
* 为用户指派角色,每次均先全部移除表中相关记录再插入
*
* 此处在用户很多的时候可能会有性能问题 ... 后面再想怎么优化
*
* @param int $user_id
* @param mixed $roleIds
*
* @return boolean
*/
function allocateRolesForUser($user_id,$roleIds){
if (empty($user_id)) return false; 

$user_id = (int) $user_id;
$roleIds = normalize($roleIds,',');
if (empty($roleIds)){
return false;
} 

SingleTableCRUD::delete($this->tbRefUsersRoles,array('user_id'=>$user_id)); 

$roleIds = array_unique($roleIds); 

foreach ($roleIds as $roleId){
SingleTableCRUD::insert($this->tbRefUsersRoles,array('user_id'=>$user_id,'role_id'=>$role_id));
}
return true;
} 

/**
* 清除用户的角色信息
*
* @param int $user_id
*
* @return boolean
*/
function cleanRolesForUser($user_id){
if (empty($user_id)) return false;
return SingleTableCRUD::delete($this->tbRefUsersRoles,array('user_id'=>(int) $user_id));
} 

/**
* 清除角色的用户关联
*
* @param int $role_id
*
* @return boolean
*/
function cleanUsersForRole($role_id){
if (empty($role_id)) return false;
return SingleTableCRUD::delete($this->tbRefUsersRoles,array('role_id'=>(int) $role_id));
} 

}
```
# 具体检测代码

```php
/**
* 对资源进行acl校验
*
* @param string $rsid 资源标识
* @param array $user 特定用户,不指定则校验当前用户
*
* @return boolean
*/
function aclVerity($rsid ,array $user = null){ 

if (empty($rsid)) return false;
if (!CoreApp::$defaultAcl) {
CoreApp::$defaultAcl = new AclFlat();
} 

$rsRow = aclGetResource($rsid); 

// 未定义资源的缺省访问策略
if (!$rsRow) return false; 

CoreApp::writeLog($rsRow,'test'); 

/*
* 校验步骤如下:
*
* 1. 先校验 资源本身 access 属性
* EVERYONE => true,NOBODY => false * 其它的属性在下面继续校验
* 2. 从 session(或者 用户session表)中获取角色id集合
* 3. 如果 用户拥有角色 则 HAS_ROLE => true , NO_ROLE => false;反之亦然
* 4. 如果资源 access == ALLOCATE_ROLES
* 1. 从缓存(或者 $tbRefResourcesRoles)中获取 资源对应的角色id集合
* 2. 将用户拥有的角色id集合 与 资源对应的角色id集合求交集
* 3. 存在交集 => true;否则 => false
*/ 

$rsRow['access'] = AclBase::formatAccessValue($rsRow['access']); 

// 允许任何人访问
if (AclBase::EVERYONE == $rsRow['access']) return true; 

// 不允许任何人访问
if (AclBase::NOBODY == $rsRow['access']) return false; 

// 获取用户信息
if (empty($user)) $user = isset($_SESSION['SI-SysUser']) ? $_SESSION['SI-SysUser'] : null; 

// 用户未登录,则当成无访问权限
if (empty($user)) return false; 

$user['roles'] = empty($user['roles']) ? null : normalize($user['roles'],';'); 

$userHasRoles = !empty($user['roles']); 

/**
* 允许 不带有角色的用户访问
*/
if (AclBase::NO_ROLE == $rsRow['access']) return $userHasRoles ? false : true; 

/**
* 允许 带有角色的用户访问
*/
if (AclBase::HAS_ROLE == $rsRow['access']) return $userHasRoles ? true : false; 

// --- 对用户进行 资源 <-> 角色 校验
if ($userHasRoles){
foreach ($user['roles'] as $role_id){
if ( aclGetRefResourcesRoles($rsid,$role_id) )
return true;
}
dump($user);
}
return false;
}
/**
* 重新生成 角色资源访问控制表
*
* @param string $actTable ACL表名称
* @param boolean $return 是否返回重新生成的列表
*
* @return mixed
*/
function aclRebuildACT($actTable ,$return = false){
if (empty($actTable)) return false; 

global $globalConf;
$rst = null;
$cacheId = null; 

switch($actTable){
case CoreApp::$defaultAcl->tbResources:
$cacheId = 'acl-resources';
$rst = SingleTableCRUD::findAll(CoreApp::$defaultAcl->tbResources);
// 转成 哈希表结构
if ($rst){
$rst = array_to_hashmap($rst,'rsid');
}
break;
case CoreApp::$defaultAcl->tbRoles:
$cacheId = 'acl-roles';
$rst = SingleTableCRUD::findAll(CoreApp::$defaultAcl->tbRoles);
// 转成 哈希表结构
if ($rst){
$rst = array_to_hashmap($rst,'id');
}
break;
case CoreApp::$defaultAcl->tbRefResourcesRoles:
$cacheId = 'acl-roles_has_resources';
$rst = SingleTableCRUD::findAll(CoreApp::$defaultAcl->tbRefResourcesRoles);
if ($rst){
$_ = array();
foreach ($rst as $row) {
$ref_id = "{$row['rsid']}<-|->{$row['role_id']}";
$_[$ref_id] = $row;
}
unset($rst);
$rst = $_;
}
break;
} 

if ($cacheId)
writeCache($globalConf['runtime']['cacheDir'] ,$cacheId ,$rst ,true); 

if ($return) return $rst;
}
/**
* 获取 角色资源访问控制表 数据
*
* @param string $actTable ACL表名称
*
* @return mixed
*/
function aclGetACT($actTable){
if (empty($actTable)) return false; 

static $rst = array(); 

$cacheId = null; 

switch($actTable){
case CoreApp::$defaultAcl->tbResources:
$cacheId = 'acl-resources';
break;
case CoreApp::$defaultAcl->tbRoles:
$cacheId = 'acl-roles';
break;
case CoreApp::$defaultAcl->tbRefResourcesRoles:
$cacheId = 'acl-roles_has_resources';
break; 

} 

if (!$cacheId) return null; 

if (isset($rst[$cacheId])) return $rst[$cacheId]; 

global $globalConf;
// 900
$rst[$cacheId] = getCache($globalConf['runtime']['cacheDir'],$cacheId,0);
if ( !$rst[$cacheId] ){
$rst[$cacheId] = aclRebuildACT($actTable,true);
} 

return $rst[$cacheId];
}
/**
* 获取 资源 记录
*
* @param string $rsid
*
* @return array
*/
function aclGetResource($rsid){
static $rst = null;
if (!$rst){
$rst = aclGetACT(CoreApp::$defaultAcl->tbResources);
if (!$rst) $rst = array();
}
return isset($rst[$rsid]) ? $rst[$rsid] : null;
}
/**
* 获取 角色 记录
*
* @param int $role_id
*
* @return array
*/
function aclGetRole($role_id){
static $rst = null;
if (!$rst){
$rst = aclGetACT(CoreApp::$defaultAcl->tbRoles);
if (!$rst) $rst = array();
}
return isset($rst[$role_id]) ? $rst[$role_id] : null;
}
/**
* 获取 用户角色关联 记录,此方法可以校验资源是否可被此角色调用
*
* @param string $rsid
* @param int $role_id
*
* @return array
*/
function aclGetRefResourcesRoles($rsid,$role_id){
static $rst = null;
if (!$rst){
$rst = aclGetACT(CoreApp::$defaultAcl->tbRefResourcesRoles);
if (!$rst) $rst = array();
}
$ref_id = "{$rsid}<-|->{$role_id}";
CoreApp::writeLog(isset($rst[$ref_id])?$rst[$ref_id]:'nodata',$ref_id);
return isset($rst[$ref_id]) ? $rst[$ref_id] : null;
}
```