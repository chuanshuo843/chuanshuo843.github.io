title: PHP依赖注入实现和应用场景
author: DuanEnJian
tags:
  - PHP
  - 设计模式
categories:
  - 开发
date: 2017-12-27 19:48:00
---
早在2004年，Martin Fowler就提出了“哪些方面的控制被反转了？”这个问题。他总结出是依赖对象的获得被反转了。基于这个结论，他为控制反转创造了一个更好的名字：依赖注入。许多非凡的应用（比HelloWorld.java更加优美，更加复杂）都是由两个或是更多的类通过彼此的合作来实现业务逻辑，这使得每个对象都需要与其合作的对象（也就是它所依赖的对象）的引用。如果这个获取过程要靠自身实现，那么如你所见，这将导致代码高度耦合并且难以测试。

<!-- more -->

# 依赖倒置原则
依赖倒置原则（Dependence Inversion Principle）是程序要依赖于抽象接口，不要依赖于具体实现。简单的说就是要求对抽象进行编程，不要对实现进行编程，这样就降低了客户与实现模块间的耦合。

**A.高层次的模块不应该依赖于低层次的模块，他们都应该依赖于抽象。**

**B.抽象不应该依赖于具体实现，具体实现应该依赖于抽象。**

# 实现方式1
**实现一个轻量级的依赖注入容器**

------
首先我们创建一个类，看起来是这样的

```php
<?php   
class Di
{
    protected $_service = [];
    public function set($name, $definition)
    {
        $this->_service[$name] = $definition;
    }
    public function get($name)
    {
        if (isset($this->_service[$name])) {
            $definition = $this->service[$name];
        } else {
            throw new Exception("Service '" . name . "' wasn't found in the dependency injection container");
        }

        if (is_object($definition)) {
            $instance = call_user_func($definition);
        }

        return $instance;
    }
}
```
现在我们已经有了一个简单的类，包含一个属性和两个方法。假设我们现在有两个类，redisDB和cache，redisDB提供一个redis数据库的操作，cache负责缓存功能的实现并且依赖于redisDB。

```php
class redisDB
{
    protected $_di;

    protected $_options;

    public function __construct($options = null)
    {
        $this->_options = $options;
    }

    public function setDI($di)
    {
        $this->_di = $di;
    }

    public function find($key, $lifetime)
    {
        // code
    }

    public function save($key, $value, $lifetime)
    {
        // code
    }

    public function delete($key)
    {
        // code
    }
}
```
在这个类中我们简单实现了redis的查询、保存和删除。你可能会有疑问，另外一个方法setDi是做什么的。待我继续为你讲解。另一个类和当前这个类结构很像：

```php
class cache
{
    protected $_di;

    protected $_options;

    protected $_connect;

    public function __construct($options = null)
    {
        $this->_options = $options;
    }

    public function setDI($di)
    {
        $this->_di = $di;
    }

    protected function _connect()
    {
        $options = $this->_options;
        if (isset($options['connect'])) {
            $service = $options['connect'];
        } else {
            $service = 'redis';
        }

        return $this->_di->get($service);
    }

    public function get($key, $lifetime)
    {
        $connect = $this->_connect;
        if (!is_object($connect)) {
            $connect = $this->_connect()
            $this->_connect = $connect;
        }
        // code
        ...
        return $connect->find($key, $lifetime);
    }

    public function save($key, $value, $lifetime)
    {
        $connect = $this->_connect;
        if (!is_object($connect)) {
            $connect = $this->_connect()
            $this->_connect = $connect;
        }
        // code
        ...
        return $connect->save($key, $lifetime);
    }

    public function delete($key)
    {
        $connect = $this->_connect;
        if (!is_object($connect)) {
            $connect = $this->_connect()
            $this->_connect = $connect;
        }
        // code
        ...
        $connect->delete($key, $lifetime);
    }
}
```
现在我们就当已经实现了redisDB和cache这两个组件，具体的细节这里就先不做讨论了，来看看如何使用使用吧。首先需要将两个组件注入到容器中：

```php
<?php
    $di = new Di();
    $di->set('redis', function() {
         return new redisDB([
             'host' => '127.0.0.1',
             'port' => 6379
         ]);
    });
    $di->set('cache', function() use ($di) {
        $cache = new cache([
            'connect' => 'redis'
        ]);
        $cache->setDi($di);
        return $cache;
    });


    // 然后在任何你想使用cache的地方
    $cache = $di->get('cache');
    $cache->get('key'); // 获取缓存数据
    $cache->save('key', 'value', 'lifetime'); // 保存数据
    $cache->delete('key'); // 删除数据
```
到这里你可能会觉得这样以来反而有点繁琐了。cache和redisDB的结构如此之像，完全可以把redis写到cache中而没必要单独分离出来？但是你想过没有，有些数据及时性没那么高而且数量比较大，用redis有点不合适，mongodb是更好的选择；有些数据更新频率更慢，对查询速度也没要求，直接写入文件保存到硬盘可能更为合适；再或者，你的客户觉得redis运维难度有点大，让你给他换成memcache... 这就是为什么把它分离出来了。然后，继续改进代码：

```php
interface BackendInterface {
    public function find($key, $lifetime);
    public function save($key, $value, $lifetime);
    public function delete($key);
}

class redisDB implements BackendInterface
{
    public function find($key, $lifetime) { }
    public function save($key, $value, $lifetime) { }
    public function delete($key) { }
}

class mongoDB implements BackendInterface
{
    public function find($key, $lifetime) { }
    public function save($key, $value, $lifetime) { }
    public function delete($key) { }
}

class file implements BackendInterface
{
    public function find($key, $lifetime) { }
    public function save($key, $value, $lifetime) { }
    public function delete($key) { }
}

$di = new Di();
//  redis
$di->set('redis', function() {
     return new redisDB([
         'host' => '127.0.0.1',
         'port' => 6379
     ]);
});
// mongodb
$di->set('mongo', function() {
     return new mongoDB([
         'host' => '127.0.0.1',
         'port' => 12707
     ]);
});
// file
$di->set('file', function() {
     return new file([
         'path' => 'path'
     ]);
});
// save at redis
$di->set('fastCache', function() use ($di) {
     $cache = new cache([
         'connect' => 'redis'
     ]);
     $cache->setDi($di);
     return $cache;
});
// save at mongodb
$di->set('cache', function() use ($di) {
     $cache = new cache([
         'connect' => 'mongo'
     ]);
     $cache->setDi($di);
     return $cache;
});
// save at file
$di->set('slowCache', function() use ($di) {
     $cache = new cache([
         'connect' => 'file'
     ]);
     $cache->setDi($di);
     return $cache;
});

// 然后在任何你想使用cache的地方 
$cache = $di->get('cache');
```
我们新增加了一个接口BackendInterface，规定了redisDB，mongoDB，file这三个类必须实现这个接口所要求的功能，至于其他锦上添花的功能，随你怎么发挥。而cache的代码，好像没有变，因为cache不需要关心数据是怎么存入数据库或者文件中。而cache的调用者，也不需要关心cache具体是怎么实现的，只要根据接口实现相应的方法就行了。多人协作你会更加受益，你们只需要商定好接口，然后分别实现就行了。

这就是依赖注入的魅力所在了，虽然看似如此简单。

以上代码还可以继续改进，直到你认为无可挑剔为止。比如，redis服务在一个请求中可能会调用多次，而每次调用都会重新创建，这将有损性能。只需扩展一下DI容器就好增加一个参数或增加一个方法，随你。

```php
class Di
{
    protected $_service = [];
    protected $_sharedService = [];
    public function set($name, $definition, $shared = false)
    {
        if ($shared) {
            $this->_sharedService[$name] = $definition;
        } else {
            $this->_service[$name] = $definition;
        }
    }
    public function get($name) {
        if (isset($this->_service[$name])) {
            $definition = $this->service[$name];
        } else if ($this->_sharedService[$name]) {
             $definition = $this->_sharedService[$name];
        } else {
            throw new Exception("Service '" . name . "' wasn't found in the dependency injection container");
        }
        ...
    }
```    
这样以来，如果某个服务在一次请求中要调用多次，你就可以将shared属性设置为true，以减少不必要的浪费。如果你觉得每次在注入时都要setDi有点繁琐，想让他自动setDi，那可以这么做：

```php
interface DiAwareInterface
{
    public function setDI($di);
    public function getDI();
}

class Di
{
    protected $service;

    public function set($name, $definition)
    {
        $this->service[$name] = $definition;
    }

    public function get($name)
    {
        ...
        if (is_object($definition)) {
            $instance = call_user_func($definition);
        }

        // 如果实现了DiAwareInterface这个接口，自动注入
        if (is_object($instance)) {
            if ($instance instanceof DiAwareInterface) {
                $instance->setDI($this);
            }
        }

        return $instance;
    }
}

class redisDB implements BackendInterface, DiAwareInterface
{
    public function find($key, $lifetime) { }
    public function save($key, $value, $lifetime) { }
    public function delete($key) { }
}
//然后，就可以这样：

$di->set('cache', function() {
    return new cache([
        'connect' => 'mongo'
    ]);
});
```
我们现在所实现的这个DI容器还很简陋，还不支持复杂的注入，你可以继续完善它。

# 实现方式2
**实现如何不考虑加载顺序**，在实现前就要明白要是不考虑加载顺序就意味着让程序自动进行加载自动进行实例化。类要实例化，只要保证完整的传递给'__construct'函数所必须的参数就OK了，在类中如果要引用其他类，也必须在构造函数中注入，否则调用时仍然会发生错误。那么我们需要一个类，来保存类实例化所需要的参数，依赖的其他类或者对象以及各个类实例化后的引用

-------
该类命名为盒子 'Container.class.php', 其内容如下

```php
/**
*    依赖注入类
*/
class Container{
    /**
    *@var array 存储各个类的定义  以类的名称为键
    */
    private $_definitions = array();

    /**
    *@var array 存储各个类实例化需要的参数 以类的名称为键
    */
    private $_params = array();

    /**
    *@var array 存储各个类实例化的引用
    */
    private $_reflections = array();

    /**
    * @var array 各个类依赖的类
    */
    private $_dependencies = array();

    /**
    * 设置依赖
    * @param string $class 类、方法 名称
    * @param mixed $defination 类、方法的定义
    * @param array $params 类、方法初始化需要的参数
    */
    public function set($class, $defination = array(), $params = array())
    {
        $this->_params[$class] = $params;
        $this->_definitions[$class] = $this->initDefinition($class, $defination);
    }

    /**
    * 获取实例
    * @param string $class 类、方法 名称
    * @param array $params 实例化需要的参数
    * @param array $properties 为实例配置的属性
    * @return mixed
    */
    public function get($class, $params = array(), $properties = array())
    {
        if(!isset($this->_definitions[$class]))
        {//如果重来没有声明过 则直接创建
            return $this->bulid($class, $params, $properties);
        }

        $defination = $this->_definitions[$class];

        if(is_callable($defination, true))
        {//如果声明是函数
            $params = $this->parseDependencies($this->mergeParams($class, $params));
            $obj = call_user_func($defination, $this, $params, $properties);
        }
        elseif(is_array($defination))
        {
            $originalClass = $defination['class'];
            unset($definition['class']);

            //difinition中除了'class'元素外 其他的都当做实例的属性处理
            $properties = array_merge((array)$definition, $properties);

            //合并该类、函数声明时的参数
            $params = $this->mergeParams($class, $params);
            if($originalClass === $class)
            {//如果声明中的class的名称和关键字的名称相同 则直接生成对象
                $obj = $this->bulid($class, $params, $properties);
            }
            else
            {//如果不同则有可能为别名 则从容器中获取
                $obj = $this->get($originalClass, $params, $properties);
            }
        }
        elseif(is_object($defination))
        {//如果是个对象 直接返回
            return $defination;
        }
        else
        {
            throw new Exception($class . ' 声明错误!');
        }
        return $obj;
    }

    /**
    * 合并参数
    * @param string $class 类、函数 名称
    * @param array $params 参数
    * @return array
    */
    protected function mergeParams($class, $params = array())
    {
        if(empty($this->_params[$class]))
        {
            return $params;
        }
        if(empty($params))
        {
            return $this->_params;
        }

        $result = $this->_params[$class];
        foreach($params as $key => $value) 
        {
            $result[$key] = $value;
        }
        return $result;
    }

    /**
    * 初始化声明
    * @param string $class 类、函数 名称
    * @param array $defination 类、函数的定义
    * @return mixed
    */
    protected function initDefinition($class, $defination)
    {
        if(empty($defination))
        {
            return array('class' => $class);
        }
        if(is_string($defination))
        {
            return array('class' => $defination);
        }
        if(is_callable($defination) || is_object($defination))
        {
            return $defination;
        }
        if(is_array($defination))
        {
            if(!isset($defination['class']))
            {
                $definition['class'] = $class;
            }
            return $defination;
        }
        throw new Exception($class. ' 声明错误');
    }

    /**
    * 创建类实例、函数
    * @param string $class 类、函数 名称
    * @param array $params 初始化时的参数
    * @param array $properties 属性
    * @return mixed
    */
    protected function bulid($class, $params, $properties)
    {
        list($reflection, $dependencies) = $this->getDependencies($class);

        foreach ((array)$params as $index => $param) 
        {//依赖不仅有对象的依赖 还有普通参数的依赖
            $dependencies[$index] = $param;
        }

        $dependencies = $this->parseDependencies($dependencies, $reflection);

        $obj = $reflection->newInstanceArgs($dependencies);

        if(empty($properties))
        {
            return $obj;
        }

        foreach ((array)$properties as $name => $value) 
        {
            $obj->$name = $value;
        }

        return $obj;
    }

    /**
    * 获取依赖
    * @param string $class 类、函数 名称
    * @return array
    */
    protected function getDependencies($class)
    {
        if(isset($this->_reflections[$class]))
        {//如果已经实例化过 直接从缓存中获取
            return array($this->_reflections[$class], $this->_dependencies[$class]);
        }

        $dependencies = array();
        $ref = new ReflectionClass($class);//获取对象的实例
        $constructor = $ref->getConstructor();//获取对象的构造方法
        if($constructor !== null)
        {//如果构造方法有参数
            foreach($constructor->getParameters() as $param) 
            {//获取构造方法的参数
                if($param->isDefaultValueAvailable())
                {//如果是默认 直接取默认值
                    $dependencies[] = $param->getDefaultValue();
                }
                else
                {//将构造函数中的参数实例化
                    $temp = $param->getClass();
                    $temp = ($temp === null ? null : $temp->getName());
                    $temp = Instance::getInstance($temp);//这里使用Instance 类标示需要实例化 并且存储类的名字
                    $dependencies[] = $temp;
                }
            }
        }
        $this->_reflections[$class] = $ref;
        $this->_dependencies[$class] = $dependencies;
        return array($ref, $dependencies);
    }

    /**
    * 解析依赖
    * @param array $dependencies 依赖数组
    * @param array $reflection 实例
    * @return array $dependencies
    */
    protected function parseDependencies($dependencies, $reflection = null)
    {
        foreach ((array)$dependencies as $index => $dependency) 
        {
            if($dependency instanceof Instance)
            {
                if ($dependency->id !== null) 
                {
                    $dependencies[$index] = $this->get($dependency->id);
                } 
                elseif($reflection !== null) 
                {
                    $parameters = $reflection->getConstructor()->getParameters();
                    $name = $parameters[$index]->getName();
                    $class = $reflection->getName();
                    throw new Exception('实例化类 ' . $class . ' 时缺少必要参数:' . $name);
                }   
            }
        }
        return $dependencies;
    }
}
```
下面是'Instance'类的内容，该类主要用于记录类的名称，标示是否需要获取实例

```php
class Instance{
    /**
     * @var 类唯一标示
     */
    public $id;

    /**
     * 构造函数
     * @param string $id 类唯一ID
     * @return void
     */
    public function __construct($id)
    {
        $this->id = $id;
    }

    /**
     * 获取类的实例
     * @param string $id 类唯一ID
     * @return Object Instance
     */
    public static function getInstance($id)
    {
        return new self($id);
    }
}
```
然后我们在'Container.class.php'中还是实现了为类的实例动态添加属性的功能，若要动态添加属性，需使用魔术方法'__set'来实现，因此所有使用依赖加载的类需要实现该方法，那么我们先定义一个基础类 'Base.class.php',内容如下

```php
class Base{
    /**
    * 魔术方法
    * @param string $name
    * @param string $value
    * @return void
    */
    public function __set($name, $value)
    {
        $this->{$name} = $value;
    }
}
```
然后我们来实现'A,B,C'类，A类的实例 依赖于 B类的实例，B类的实例依赖于C类的实例

```php
//A.class.php
class A extends Base{
    private $instanceB;

    public function __construct(B $instanceB)
    {
        $this->instanceB = $instanceB;
    }

    public function test()
    {
        $this->instanceB->test();
    }
}
//B.class.php
class B  extends Base{
    private $instanceC;

    public function __construct(C $instanceC)
    {
        $this->instanceC = $instanceC;
    }

    public function test()
    {
        return $this->instanceC->test();
    }
}
//C.class.php
class C  extends Base{
    public function test()
    {
        echo 'this is C!';
    }
}
```
然后我们在'index.php'中获取'A'的实例，要实现自动加载，需要使用SPL类库的'spl_autoload_register'方法，代码如下

```php
function autoload($className)
{
    include_once $className . '.class.php';
}
spl_autoload_register('autoload', true, true);
$container = new Container;

$a = $container->get('A');
$a->test();//输出 'this is C!'
```

上面的例子看起来是不是很爽，根本都不需要考虑'B','C' (当然，这里B，C 除了要使用相应类的实例外，没有其他参数，如果有其他参数，必须显要调用'$container->set(xx)'方法进行注册，为其制定实例化必要的参数)。有细心同学可能会思考，比如我在先获取了'A'的实例，我在另外一个地方也要获取'A'的实例，但是这个地方'A'的实例需要其中某个属性不一样，我怎么做到？

你可以看到'Container' 类的 'get' 方法有其他两个参数，'$params' 和 '$properties' ， 这个'$properties' 即可实现刚刚的需求，这都依赖'__set'魔术方法，当然这里你不仅可以注册类，也可以注册方法或者对象，只是注册方法时要使用回调函数，例如

```php
$container->set('foo', function($container, $params, $config){
    print_r($params);
    print_r($config);
});

$container->get('foo', array('name' => 'foo'), array('key' => 'test'));
```
还可以注册一个对象的实例，例如

```php
class Test
{
    public function mytest()
    {
        echo 'this is a test';
    }
}

$container->set('testObj', new Test());

$test = $container->get('testObj');
$test->mytest();
```
以上自动加载，依赖控制的大体思想就是将类所要引用的实例通过构造函数注入到其内部，在获取类的实例的时候通过PHP内建的反射解析构造函数的参数对所需要的类进行加载，然后进行实例化，并进行缓存以便在下次获取时直接从内存取得

# 应用实例
```php
<?php
namespace Server\PromotionExtend\Lib;

class DI implements \ArrayAccess{

    private static $_instance;
    protected $_service = [];
    protected $_sharedService = [];

    //单例方法,用于访问实例的公共的静态方法
    public static function getInstance(){
        if(!(self::$_instance instanceof self)){
            self::$_instance = new self;
        }
        return self::$_instance;
    }

    public function __clone(){
        trigger_error('Clone is not allow!',E_USER_ERROR);
    }

    /**
     * 获取服务
     *
     * @param $name
     * @return mixed|null|object
     */
    public function get($name){
        //先从已经实例化的列表中查找
        if(isset($this->_service[$name])){
            return $this->_service[$name];
        }
        //检测有没有注册该服务
        if( ! isset($this->_sharedService[$name])){
            trigger_error("Service {$name} Not Find !!!\n");
            return null;
        }
        $concrete = $this->_sharedService[$name]['class'];//对象具体注册内容
        $params = $this->_sharedService[$name]['params'];//配置
        $obj = null;
        //匿名函数方式
        if($concrete instanceof \Closure){
            $obj = call_user_func_array($concrete,$params);
        }elseif(is_string($concrete)){//字符串方式
            if(empty($params)){
                $obj = new $concrete;
            }else{
                //带参数的类实例化，使用反射
                $class = new \ReflectionClass($concrete);
                $obj = $class->newInstanceArgs($params);
            }
        }
        //如果是共享服务，则写入_instances列表，下次直接取回
        if($this->_sharedService[$name]['shared'] == true && $obj){
            $this->_service[$name] = $obj;
        }
        return $obj;
    }
    /**
     * 检测是否已经绑定
     *
     * @param $name
     * @return bool
     */
    public function has($name){
        return isset($this->_sharedService[$name]) or isset($this->_service[$name]);
    }
    /**
     * 卸载服务
     *
     * @param $name
     * @return bool
     */
    public function remove($name){
        unset($this->_sharedService[$name],$this->_service[$name]);
        return true;
    }
    /**
     * 设置服务
     *
     * @param $name
     * @param $class
     * @param $params
     * @return bool
     */
    public function set($name, $class, $params = array()){
        $this->registerService($name, $class, $params);
        return true;
    }
    /**
     * 设置共享服务
     *
     * @param $name
     * @param $class
     * @param $params
     */
    public function setShared($name, $class, $params = array()){
        $this->registerService($name, $class, $params, true);
    }
    /**
     * 注册服务
     *
     * @param $name
     * @param $class
     * @param $params
     * @param bool|false $shared
     */
    private function registerService($name, $class, $params = array(), $shared = false){
        $this->remove($name);
        if( ! ($class instanceof \Closure) && is_object($class)){
            $this->_service[$name] = $class;
        }else{
            $this->_sharedService[$name] = array('class'=>$class,'shared'=>$shared,'params'=>$params);
        }
    }
    /**
     * ArrayAccess接口,检测服务是否存在
     *
     * @param mixed $offset
     * @return bool
     */
    public function offsetExists($offset){
        return $this->has($offset);
    }
    /**
     * ArrayAccess接口,以$di[$name]方式获取服务
     *
     * @param mixed $offset
     * @return mixed|null|object
     */
    public function offsetGet($offset){
        return $this->get($offset);
    }
    /**
     * ArrayAccess接口,以$di[$name]=$value方式注册服务，非共享
     *
     * @param mixed $offset
     * @param mixed $value
     * @return bool
     */
    public function offsetSet($offset, $value){
        return $this->set($offset,$value);
    }
    /**
     * ArrayAccess接口,以unset($di[$name])方式卸载服务
     *
     * @param mixed $offset
     * @return bool
     */
    public function offsetUnset($offset){
        return $this->remove($offset);
    }
}
//使用
class DiTest(){
    public function test(){
        $di = Di::getInstance();
        //直接实例化注册(不建议)
        $redis = new Redis($config['redis']['test']);
        $di->setShared('redis', $redis);
        //或
        //以数组方式注入服务，实例化非共享
        $di['redis'] = $redis;
        
        /*------------------------------------------------*/
        
        //延迟实例化注册
        $di->setShard('redis', function() use(config) {
        	return new Redis($config['redis']['test']);
        });
        //或
        $di->setShard('redis', 'Redis', $config['redis']['test']);
        //或
        $di['redis'] = function() use ($config) {
        	return new Redis($config['redis']['test']);
        };
    }  
}    
```