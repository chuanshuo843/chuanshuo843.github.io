title: RabbitMQ概述
author: o时过境迁心难沉
abbrlink: c80a4ce4
tags:
  - PHP
  - 其他
categories:
  - 开发
date: 2018-08-29 14:11:00
---
rabbitMQ是一款基于AMQP协议的消息中间件，它能够在应用之间提供可靠的消息传输。在易用性，扩展性，高可用性上表现优秀。使用消息中间件利于应用之间的解耦，生产者（客户端）无需知道消费者（服务端）的存在。而且两端可以使用不同的语言编写，大大提供了灵活性。

<!-- more -->
![upload successful](/images/jianjie_sss.png)

# 交换机
## 直连交换机
直连交换机是一种带路由功能的交换机，一个队列会和一个交换机绑定，除此之外再绑定一个routing_key，当消息被发送的时候，需要指定一个binding_key，这个消息被送达交换机的时候，就会被这个交换机送到指定的队列里面去。同样的一个binding_key也是支持应用到多个队列中的。

![upload successful](/images/zhilian_sss.png)
## 扇形交换机
扇形交换机是最基本的交换机类型，它所能做的事情非常简单———广播消息。扇形交换机会把能接收到的消息全部发送给绑定在自己身上的队列。因为广播不需要“思考”，所以扇形交换机处理消息的速度也是所有的交换机类型里面最快的。

![upload successful](/images/shanxing_ssss.png)
## 主题交换机
主题交换机通过模式匹配分配消息的路由键属性，将路由键和某个模式进行匹配，此时队列需要绑定到一个模式上。它将路由键和绑定键的字符串切分成单词，这些单词之间用点隔开。它同样也会识别两个通配符：符号“#”和符号“*”。#匹配0个或多个单词，*匹配不多不少一个单词。

![upload successful](/images/zhuti_sss.png)
## 首部交换机
首部交换机是忽略routing_key的一种路由方式。路由器和交换机路由的规则是通过Headers信息来交换的，这个有点像HTTP的Headers。将一个交换机声明成首部交换机，绑定一个队列的时候，定义一个Hash的数据结构，消息发送的时候，会携带一组hash数据结构的信息，当Hash的内容匹配上的时候，消息就会被写入队列。
绑定交换机和队列的时候，Hash结构中要求携带一个键“x-match”，这个键的Value可以是any或者all，这代表消息携带的Hash是需要全部匹配(all)，还是仅匹配一个键(any)就可以了。相比直连交换机，首部交换机的优势是匹配的规则不被限定为字符串(string)。

# 虚拟主机,交换机,队列,绑定
- 虚拟主机：一个虚拟主机持有一组交换机、队列和绑定。为什么需要多个虚拟主机呢？很简单，RabbitMQ当中，用户只能在虚拟主机的粒度进行权限控制。 因此，如果需要禁止A组访问B组的交换机/队列/绑定，必须为A和B分别创建一个虚拟主机。每一个RabbitMQ服务器都有一个默认的虚拟主机“/”。
- 交换机：Exchange 用于转发消息，但是它不会做存储 ，如果没有 Queue bind 到 Exchange 的话，它会直接丢弃掉 Producer 发送过来的消息。常用交换机又分为3种- - 类型：Direct Exchange，Topic Exchange，Fanout Exchange。
- 绑定：也就是交换机需要和队列相绑定，这其中如上图所示，是多对多的关系。

# 消息确认与持久化
- 基于现在的代码,一旦RabbitMQ将消息发送给了消费者,就会从内存中删除,这时候如果正在执行任务的消费者挂了,会丢失消息,也无法把它讲给另外一个消费者去处理.
- 所以为了确保消息不丢失,RabbitMQ支持消息应答.消费者发送一个消息应答,告诉RabbitMQ这个消息已经接收并处理完了.
- 如果一个消费者挂掉却没有发送应答，RabbitMQ会理解为这个消息没有处理完全，然后交给另一个消费者去重新处理,十分可靠.

在之前,我们会使用 channel.basicConsume(channelName,true,consumer) ,true表示接收到消息后,会自动反馈消息给服务器.那么首先我们要将autoAck关闭,等我们处理完消息,手动去确认.

```
QueueingConsumer consumer = new QueueingConsumer(channel);
boolean autoAck = false;
channel.basicConsume("hello", autoAck, consumer);
```
接着手动确认

```
channel.basicAck(delivery.getEnvelope().getDeliveryTag() , false);
```
现在我们确保了消费者死亡,任务也不会丢失.但是如果整个rabbitMQ服务器都挂了,那消息还是会丢失.所以有时候我们需要让消息持久化.

```
boolean durable = true;
channel.queueDeclare(channelName, durable, false, false, null);
```
我们的队列已经不会丢失了,还需要在生产者里将消息标记为持久性的

```
MessageProperties.PERSISTENT_TEXT_PLAIN 
```
# 实例代码
Rabbitmq.php
```
<?php

namespace app\common\library;

use PhpAmqpLib\Channel\AMQPChannel;
use PhpAmqpLib\Connection\AMQPStreamConnection;
use PhpAmqpLib\Message\AMQPMessage;
use PhpAmqpLib\Wire\AMQPTable;
use think\Config;
use think\Log;

class Rabbitmq
{
    /**
     * 配置
     *
     * @var array
     */
    public $config;


    /**
     * @var AMQPChannel
     */
    public $channel;

    /**
     * initialized
     *
     * @var AMQPStreamConnection
     */
    public $connect;


    public function __construct(array $config = [])
    {
        $this->config = array_merge(Config::get('rabbitmq'), $config);
    }

    /**
     * 处理消息格式  A Message for use with the Channnel.basic_* methods.
     *
     * @param $msg
     * @param $message_durable
     * @return AMQPMessage
     */
    public function message($msg, $message_durable)
    {
        if (is_array($msg)) {
            $msg = json_encode($msg);
        }
        if (!is_object($msg) && $message_durable === true) {
            return new AMQPMessage($msg, ['delivery_mode' => AMQPMessage::DELIVERY_MODE_PERSISTENT]);
        }
        return new AMQPMessage($msg);
    }

    /**
     * acknowledge one or more messages
     *
     * @param string $delivery_tag
     */
    public function basicAck($delivery_tag)
    {
        $this->channel->basic_ack($delivery_tag);
    }


    /**
     * 生产者 生产实时队列 只生产一个队列
     *
     * @param        $data
     * @param        $queue
     * @param        $exchange_name
     * @param string $routing_key
     * @param string $type
     * @param bool   $queue_durable
     * @param bool   $message_durable
     */
    public function send(
        $data, $queue, $exchange_name, $routing_key = '', $type = 'direct', $queue_durable = false, $message_durable = false
    ) {
        $this->connect = new AMQPStreamConnection(
            $this->config['host'],
            $this->config['port'],
            $this->config['login'],
            $this->config['password'],
            $this->config['vhost']
        );
        $this->channel = $this->connect->channel();

        //声明交换机
        $this->channel->exchange_declare($exchange_name, $type, false, $message_durable, false, false, false, [], null);

        //声明队列
        $this->channel->queue_declare($queue, false, $queue_durable, false, false, false, [], null);

        //绑定交换机与队列
        $this->channel->queue_bind($queue, $exchange_name, $routing_key, false, [], null);

        //处理压入消息格式
        $msg = $this->message($data, $message_durable);

        //压入消息到交换机
        $this->channel->basic_publish($msg, $exchange_name, $routing_key, false, false, null);

        //关闭
        $this->channel->close(); // 关闭信道
        $this->connect->close(); // 关闭链接
    }

    /**
     * 延时生产者 生产延时队列 生产两个队列（1个延时死信队列，1个实时消费队列）
     *
     * @param  array|string $data  消息内容
     * @param string        $delay_queue  延时队列
     * @param string        $delay_exchange_name 延时交换机
     * @param string        $delay_routing_key 延时队列routing_key
     * @param string        $delay_type 延时交换机类型
     * @param int           $delay_expire 延时队列声明周期（过期会触发死信规则）
     * @param bool          $delay_queue_durable 延时队列持久化
     * @param bool          $delay_message_durable 延时消息持久化
     * @param string        $receive_queue 接收队列（接收死信规则）
     * @param string        $receive_exchange_name 接收交换机
     * @param string        $receive_routing_key 接收队列routing_key
     * @param string        $receive_type 接收交换机类型
     * @param bool          $receive_queue_durable 接收队列持久化
     * @param bool          $receive_message_durable 接收消息持久化
     */
    public function sendDelay(
        $data,
        $delay_queue,
        $delay_exchange_name,
        $delay_routing_key = '',
        $delay_type = 'direct',
        $delay_expire = 0,
        $delay_queue_durable = false,
        $delay_message_durable = false,
        $receive_queue,
        $receive_exchange_name,
        $receive_routing_key = '',
        $receive_type = 'direct',
        $receive_queue_durable = false,
        $receive_message_durable = false
    ) {
        $this->connect = new AMQPStreamConnection(
            $this->config['host'],
            $this->config['port'],
            $this->config['login'],
            $this->config['password'],
            $this->config['vhost']
        );
        $this->channel = $this->connect->channel();

        // 声明主队列 <--  关联主消费交换机(接收)  <-- 数据压入
        //  |  300        /
        //  |            /
        //  关联延时交换机    ->   关联消费队列
        //
        //  延时交换机（弹出数据） -> 消费

        //声明死信规则
        $tale = new AMQPTable();
        $tale->set('x-dead-letter-exchange', $receive_exchange_name);
        $tale->set('x-dead-letter-routing-key', $receive_routing_key);
        $tale->set('x-message-ttl', $delay_expire);

        //声明延时交换机 与 接收交换机
        $this->channel->exchange_declare($delay_exchange_name, $delay_type, false, $delay_message_durable, false, false, false, [], null);
        $this->channel->exchange_declare($receive_exchange_name, $receive_type, false, $receive_message_durable, false, false, false, [], null);

        //声明延时队列 与 接收队列
        $this->channel->queue_declare($delay_queue, false, $delay_queue_durable, false, false, false, $tale, null);
        $this->channel->queue_declare($receive_queue, false, $receive_queue_durable, false, false, false, [], null);

        //绑定延时队列到延时交换机 与 绑定接收队列到接收交换机
        $this->channel->queue_bind($delay_queue, $delay_exchange_name, $delay_routing_key, false, [], null);
        $this->channel->queue_bind($receive_queue, $receive_exchange_name, $receive_routing_key, false, [], null);

        //处理压入消息格式
        $msg = $this->message($data, $delay_message_durable);

        //压入消息到交换机
        $this->channel->basic_publish($msg, $delay_exchange_name, $delay_routing_key, false, false, null);

        //关闭
        $this->channel->close(); // 关闭信道
        $this->connect->close(); // 关闭链接
    }

    /**
     * 消费者 只消费一个队列
     *
     * @param string $queue
     * @param string $consumer_tag
     * @param bool   $no_local
     * @param bool   $no_ack
     * @param bool   $exclusive
     * @param bool   $nowait
     * @param null   $ticket
     * @param array  $arguments
     */
    function receive(
        $queue = '', // 队列名
        $callback = null, // 回调函数
        $queue_durable = false, //持久化
        $consumer_tag = '',
        $no_local = false,
        $no_ack = false,
        $exclusive = false, //队列是否可以被其他队列访问
        $nowait = false,
        $ticket = null,
        $arguments = array()
    ) {
        $this->connect = new AMQPStreamConnection(
            $this->config['host'],
            $this->config['port'],
            $this->config['login'],
            $this->config['password'],
            $this->config['vhost']
        );
        $this->channel = $this->connect->channel();

        //一次只消费一个
        $this->channel->basic_qos(0,1,false);

        //声明队列
        $this->channel->queue_declare($queue, false, $queue_durable, false, false, false, [], null);

        //订阅消费 callback仅绑定并不立即执行
        $this->channel->basic_consume($queue, $consumer_tag, $no_local, $no_ack, $exclusive, $nowait, $callback,
            $ticket, $arguments);

        //轮训等待并触发basic_consume绑定的callback
        while (count($this->channel->callbacks)) {
            $this->channel->wait();
        }

        //关闭
        $this->channel->close(); // 关闭信道
        $this->connect->close(); // 关闭链接
    }

//        $callback = function ($msg) {
//            $rabbit = new \app\admin\command\Rabbitmq();
//            $rabbit->sendMessage($msg->body);
////            $recharge = new Recharge();
////            $recharge->sendMessage($msg->body);
//            $this->basicAck($msg->delivery_info['delivery_tag']);
//        };

}

```
消费队列

```
 	  /**
     * MQ队列处理方法
     */
    protected function executeMQ(){
        try {
            $mq = new Rabbitmq();
            $mq->receive(self::SYNC_MQ_QUEUE_NAME, function (AMQPMessage $msg){
                $data = json_decode($msg->body, true);
                if(isset($data['channel_id']) && !empty($data['channel_id'])){
                    $channel = $msg->delivery_info['channel'];
                    if($is_end = $this->sync($data['channel_id'])){
                        //手动ACK回复
                        $channel->basic_ack($msg->delivery_info['delivery_tag']);
                    }else{
                        //拒绝消息,并丢弃
                        $channel->basic_nack($msg->delivery_info['delivery_tag'],false,false);
                        //五秒后重新拉取
                        sleep(5);
                    }
                }
            });
        } catch (\Exception $e) {
            Log::error("MQ 同步用户 触发异常！message:" . $e->getMessage());
            $this->consoleOut->writeln("MQ 同步用户 触发异常！message:" . $e->getMessage());
        }
    }
```
添加队列
```
$mq = new Rabbitmq();

$delaytime = Config::get('rabbitmq.pay_cannel_expire')*1000*3; //15分钟 队列延迟时间/单位毫秒
$delay_q = 'Q_NewPayCancelDelay';
$delay_e = 'E_NewPayCancelDelay';
$receive_q = 'Q_NewPayCancelReceive';
$receive_e = 'E_NewPayCancelReceive';
//延时队列
$mq->sendDelay($data, $delay_q, $delay_e, '', 'direct', $delaytime, false, false,$receive_q, $receive_e, '', 'direct', false, false);
//及时队列
$mq->send(['channel_id'=>$channel_id,'appid'=>$appid],self::SYNC_MQ_QUEUE_NAME,self::SYNC_MQ_EXCHANGE_NAME);

```
# 参考资料

[RabbitMQ发布订阅实战-实现延时重试队列](https://segmentfault.com/a/1190000014847788)

[RabbitMQ的四种交换机](https://www.jianshu.com/p/469f4608ce5d)

[rabbitmq之python_pika模块连接MQ使用](https://www.cnblogs.com/cwp-bg/p/8426188.html)

[RabbitMQ 使用参考](https://www.zouyesheng.com/rabbitmq.html)