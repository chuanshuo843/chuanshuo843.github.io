title: PHP的装饰器模式实现
author: DuanEnJian
tags:
  - PHP
  - 设计模式
categories:
  - 开发
date: 2017-12-27 21:00:00
---
修饰模式，是面向对象编程领域中，一种动态地往一个类中添加新的行为的设计模式。就功能而言，修饰模式相比生成子类更为灵活，这样可以给某个对象而不是整个类添加一些功能。将所有的功能建立在继承体系上会导致系统中的类越来越多，而且当你又要修改他们的分支的时候，可能还会出现重复代码

<!-- more -->
# 概念
扩展一个类一般可以使用继承或者组合的形式。使用继承的方式扩展时，随着基类子类的增多，以及子类的子类出现，继而出现了代码的无限制膨胀，增加了系统的复杂性。而使用装饰者模式既继承又引用，能动态扩展类的一些功能，减少了继承数量。

- 装饰器模式（Decorator），可以动态地添加修改类的功能 

- 一个类提供了一项功能，如果要在修改并添加额外的功能，传统的编程模式，需要写一个子类继承它，并重新实现类的方法

- 使用装饰器模式，仅需在运行时添加一个装饰器对象即可实现，可以实现最大的灵活性。

# 实现方式
实现一个装饰器的基类
```php
//画图装饰器
interface DrawDecorator
{
    //画之前的操作
    function beforeDraw();

    //画之后的操作
    function afterDraw();
}
```
实现一个颜色装饰器
```php
class ColorDrawDecorator implements DrawDecorator
{
    //颜色属性
    protected $color;

    //初始化颜色
    function __construct($color = 'red')
    {
        $this->color = $color;
    }

    //画之前的操作
    function beforeDraw()
    {
        echo "<div style='color: {$this->color};'>";
    }

    //画之后的操作
    function afterDraw()
    {
        echo "</div>";
    }
}
```
实现画板的类
```php
class Canvas
    {
        //保存点阵的一个数组
        public $data;

        //保存装饰器对象
        protected $decorators = array();

        //初始化点阵
        function init($width = 20, $height = 10)
        {
            $data = array();
            for($i = 0; $i < $height; $i++)
            {
                for($j = 0; $j < $width; $j++)
                {
                    $data[$i][$j] = '*';
                }
            }
            $this->data = $data;
        }

        //注册装饰器对象
        function addDecorator(DrawDecorator $decorator)
        {
            $this->decorators[] = $decorator;
        }

        //画之前的操作
        function beforeDraw()
        {
            foreach($this->decorators as $decorator)
            {
                $decorator->beforeDraw();
            }
        }

        //画之后的操作
        function afterDraw()
        {
            $decorators = array_reverse($this->decorators);
            foreach($decorators as $decorator)
            {
                $decorator->afterDraw();
            }
        }

        //开始画图
        function draw()
        {
            $this->beforeDraw();
            foreach($this->data as $line)
            {
                foreach($line as $char)
                {
                    echo $char;
                }
                echo "<br />\n";
            }
            $this->afterDraw();
        }

        //描述一个矩形的点阵
        function rect($a1, $a2, $b1, $b2)
        {
            foreach($this->data as $k1 => $line)
            {
                if ($k1 < $a1 or $k1 > $a2) continue;
                foreach($line as $k2 => $char)
                {
                    if ($k2 < $b1 or $k2 > $b2) continue;
                    $this->data[$k1][$k2] = '&nbsp;';
                }
            }
        }
    }
```
调用
```php
$canvas = new Canvas();
//注入装饰器对象
$canvas->addDecorator(new ColorDrawDecorator('green'));
$canvas->init(40, 20);

$canvas->rect(4,15,9,30);
$canvas->draw();
//同样如果你还想使用加粗，倾斜，设置自定义标题等等，就在创建一个特定的装饰器，注入到画布内就可以实现了
```