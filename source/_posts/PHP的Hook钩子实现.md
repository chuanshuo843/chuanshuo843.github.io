title: PHP的Hook钩子实现
author: DuanEnJian
tags:
  - PHP
categories:
  - 开发
date: 2017-12-27 20:27:00
---
钩子就像一个”陷阱”、”监听器”,当A发送一个消息到B时，当消息还未到达目的地B时，被钩子拦截调出一部分代码做处理，这部分代码也叫钩子函数或者回调函数

<!-- more -->
# Hook核心类
这个类要放在全局引用里面，在所有需要用到插件的地方，优先加载。
```
<?php
/**
*
* 插件机制的实现核心类

*/
class PluginManager
{
    /**
     * 监听已注册的插件
     *
     * @access private
     * @var array
     */
    private $_listeners = array();
     /**
     * 构造函数
     *
     * @access public
     * @return void
     */
    public function __construct()
    {
        #这里$plugin数组包含我们获取已经由用户激活的插件信息
     #为演示方便，我们假定$plugin中至少包含
     #$plugin = array(
        #    'name' => '插件名称',
        #    'directory'=>'插件安装目录'
        #);
        $plugins = get_active_plugins();#这个函数请自行实现
        if($plugins)
        {
            foreach($plugins as $plugin)
            {//假定每个插件文件夹中包含一个actions.php文件，它是插件的具体实现
                if (@file_exists(STPATH .'plugins/'.$plugin['directory'].'/actions.php'))
                {
                    include_once(STPATH .'plugins/'.$plugin['directory'].'/actions.php');
                    $class = $plugin['name'].'_actions';
                    if (class_exists($class))
                    {
                        //初始化所有插件
                        new $class($this);
                    }
                }
            }
        }
        #此处做些日志记录方面的东西
    }

    /**
     * 注册需要监听的插件方法（钩子）
     *
     * @param string $hook
     * @param object $reference
     * @param string $method
     */
    function register($hook, &$reference, $method)
    {
        //获取插件要实现的方法
        $key = get_class($reference).'->'.$method;
        //将插件的引用连同方法push进监听数组中
        $this->_listeners[$hook][$key] = array(&$reference, $method);
        #此处做些日志记录方面的东西
    }
    /**
     * 触发一个钩子
     *
     * @param string $hook 钩子的名称
     * @param mixed $data 钩子的入参
     *    @return mixed
     */
    function trigger($hook, $data='')
    {
        $result = '';
        //查看要实现的钩子，是否在监听数组之中
        if (isset($this->_listeners[$hook]) && is_array($this->_listeners[$hook]) && count($this->_listeners[$hook]) > 0)
        {
            // 循环调用开始
            foreach ($this->_listeners[$hook] as $listener)
            {
                // 取出插件对象的引用和方法
                $class =& $listener[0];
                $method = $listener[1];
                if(method_exists($class,$method))
                {
                    // 动态调用插件的方法
                    $result .= $class->$method($data);
                }
            }
        }
        #此处做些日志记录方面的东西
        return $result;
    }
}
```
# Hook插件实现
接下来是一个简单插件的实现DEMO。这是一个简单的Hello World插件，用于输出一句话。
```
<?php
/**
* 这是一个Hello World简单插件的实现
*/
/**
*需要注意的几个默认规则：
*    1. 本插件类的文件名必须是action
*    2. 插件类的名称必须是{插件名_actions}
*/
class DEMO_actions
{
    //解析函数的参数是pluginManager的引用
    function __construct(&$pluginManager)
    {
        //注册这个插件
        //第一个参数是钩子的名称
        //第二个参数是pluginManager的引用
        //第三个是插件所执行的方法
        $pluginManager->register('demo', $this, 'say_hello');
    }

    function say_hello()
    {
        echo 'Hello World';
    }
}
```
# 调用插件
再接下来就是插件的调用触发的地方，比如我要将say_hello放到我博客首页Index.php， 那么你在index.php中的某个位置写下：
```php
<?php
$pluginManager->trigger('demo','');

```
第一个参数表示钩子的名字，第二个参数是插件对应方法的入口参数，由于这个例子中没有输入参数，所以为空。