title: Kubernetes集群部署方案
author: DuanEnJian
tags:
  - Linux
  - Docker
categories:
  - 运维
date: 2017-12-28 20:44:00
---
Docker的流行激活了一直不温不火的 PaaS，随之而来的是各类 Micro-PaaS的出现，Kubernetes是其中最具代表性的一员，它是 Google多年大规模容器管理技术的开源版本。越来越多的企业被迫面对互联网规模所带来的各类难题，而 Kubernetes以其优秀的理念和设计正在逐步形成新的技术标准，对于任何领域的运营总监、架构师和软件工程师来说，都是一个绝佳的突破机会。
<!-- more -->
# 准备工作
etcd下载:https://github.com/coreos/etcd/releases
flannel下载:https://github.com/coreos/flannel/releases
docker下载:https://github.com/docker/docker/releases
kubernetes下载:https://github.com/kubernetes/kubernetes/releases

**三台centos主机**
**k8s master: 10.11.151.97  tc-151-97**
**k8s node1: 10.11.151.100  tc-151-100**
**k8s node2: 10.11.151.101  tc-151-101**
# ETCD集群部署
ETCD是k8s集群的基础，可以单结点也可以以集群的方式部署。本文以三台主机组成ETCD集群进行部署，以service形式启动。在三台主机上分别执行如下操作
## 创建工作目录
解压ETCD安装包并将etcd和etcdctl复制到工作目录下（本文工作目录为/opt/domeos/openxxs/k8s-1.1.3-flannel）。
## 创建Service
创建 /lib/systemd/system/etcd.service 文件，该文件为centos系统的服务文件，注意配置其中的etcd可执行文件的绝对路径
```bash
[Unit]
Description=ETCD

[Service]
Type=notify
EnvironmentFile=/etc/sysconfig/etcd
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/etcd $ETCD_NAME \
          $INITIAL_ADVERTISE_PEER_URLS \
          $LISTEN_PEER_URLS \
          $ADVERTISE_CLIENT_URLS \
          $LISTEN_CLIENT_URLS \
          $INITIAL_CLUSTER_TOKEN \
          $INITIAL_CLUSTER \
          $INITIAL_CLUSTER_STATE \
          $ETCD_OPTS
Restart=on-failure
```
## 设置配置文件
创建 /etc/sysconfig/etcd 文件，该文件为服务的配置文件，三台主机的ETCD_NAME、INITIAL_ADVERTISE_PEER_URLS和ADVERTISE_CLIENT_URLS参数各不相同，下面为97机上的配置文件，100和101上要做相应修改
```bash
# configure file for etcd

# -name
ETCD_NAME='-name k8sETCD0'
# -initial-advertise-peer-urls
INITIAL_ADVERTISE_PEER_URLS='-initial-advertise-peer-urls http://10.11.151.97:4010'
# -listen-peer-urls
LISTEN_PEER_URLS='-listen-peer-urls http://0.0.0.0:4010'
# -advertise-client-urls
ADVERTISE_CLIENT_URLS='-advertise-client-urls http://10.11.151.97:4011,http://10.11.151.97:4012'
# -listen-client-urls
LISTEN_CLIENT_URLS='-listen-client-urls http://0.0.0.0:4011,http://0.0.0.0:4012'
# -initial-cluster-token
INITIAL_CLUSTER_TOKEN='-initial-cluster-token k8s-etcd-cluster'
# -initial-cluster
INITIAL_CLUSTER='-initial-cluster k8sETCD0=http://10.11.151.97:4010,k8sETCD1=http://10.11.151.100:4010,k8sETCD2=http://10.11.151.101:4010'
# -initial-cluster-state
INITIAL_CLUSTER_STATE='-initial-cluster-state new'
# other parameters
ETCD_OPTS=''
```
## 配置网络环境
启动集群前如果网络环境配置存在冲突，特别是iptables规则的干涉，会导致集群工作不正常。因此在启动前需要确认如下配置

* 关闭防火墙

```bash
systemctl stop firewalld.service
```
* 修改hosts
kubelet 是通过/etc/hosts来获取本机IP的，因此需要在/etc/hosts中配置hostname和IP的对应关系，如97机上的 /etc/hosts 中需要存在这条记录

```bash
10.11.151.97   tc-151-97

#hostname在k8s的网络配置中是个很重要的参数，要求其满足DNS的命名规则，可由字母数字短横线组成，但下划线不行（如tc_151_97就是不符合要求的）。在主机上通过执行 hostname 命令查看本机的hostname，如果不符合要求，有两种解决方案：

#<1>直接更改主机的hostname使其符合要求，更改过程中需要重启网络，

#<2>在启动kubelet时使用 --hostname_override 参数指定用于集群内的hostname，在已有其它服务依赖于主机hostname的情形下推荐使用这种方式。
```
## 启动Etcd
启动ETCD集群
```bash
systemctl daemon-reload
systemctl start etcd
```
## 测试Etcd
```bash
# 查看服务状态
systemctl status -l etcd
# 若正常，则显示 Active: active (running)，同时在日志的最后会提示当前结点已加入到集群中了，如 "the connection with 6adad1923d90fb38 became active"
# 如果各个ETCD结点间系统时间相差较大则会提示"the clock difference against ... peer is too high"，此时根据需要修正系统时间

# 查看集群结点的访问是否正常
curl -L http://10.11.151.97:4012/version
curl -L http://10.11.151.100:4012/version
curl -L http://10.11.151.101:4012/version
# 若正常，则返回: {"etcdserver":"2.2.1","etcdcluster":"2.2.0"}
```
# 安装Kubernetes Master
k8s-master一般包括三个组件：kube-apiserver、kube-controller-manager 和 kube-scheduler。如果要将k8s-master所在的主机也加入集群管理中，比如让这台主机可以使用集群内的DNS服务等，则需要在这台主机上启动kube-proxy，本文不考虑这种情况。将安装包解压后，复制 解压目录/bin/linux/amd64/ 下的 kube-apiserver、kube-controller-manager 和 kube-scheduler 到工作目录中。
## 创建kube-apiserver.Service
/lib/systemd/system/kube-apiserver.service 文件，同样需要注意将kube-apiserver可执行文件的绝对路径配置一下

```bash
[Unit]
Description=kube-apiserver

[Service]
EnvironmentFile=/etc/sysconfig/kube-apiserver
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/kube-apiserver $ETCD_SERVERS \
          $LOG_DIR \
          $SERVICE_CLUSTER_IP_RANGE \
          $INSECURE_BIND_ADDRESS \
          $INSECURE_PORT \
          $BIND_ADDRESS \
          $SECURE_PORT \
          $AUTHORIZATION_MODE \
          $AUTHORIZATION_FILE \
          $BASIC_AUTH_FILE \
          $KUBE_APISERVER_OPTS
Restart=on-failure
```
## 设置kube-apiserver配置文件
**事实上只要配置了ETCD_SERVERS一项其它全留空也足以让kube-apiserver正常跑起来了。ETCD_SERVERS也并不需要将ETCD集群的所有结点服务地址写上，但至少要有一个。**

如果不需要使用 https 进行认证和授权，则可以不配置BIND_ADDRESS、SECURE_PORT、AUTHORIZATION_MODE、AUTHORIZATION_FILE和BASIC_AUTH_FILE。关于安全认证和授权在k8s官方文档里给出了很详细的介绍（authorization   [戳这里](http://kubernetes.io/v1.1/docs/admin/authorization.html) ，authentication   [戳这里](http://kubernetes.io/v1.1/docs/admin/authentication.html) ），本文的配置方式以ABAC（用户配置认证策略）进行认证，同时明文存储了密码。两个配置文件的内容如下

```bash
# /opt/domeos/openxxs/k8s-1.1.3-flannel/authorization的内容：
{"user": "admin"}

# /opt/domeos/openxxs/k8s-1.1.3-flannel/authentication.csv的内容，共三列（密码，用户名，用户ID）：
admin,admin,adminID
```
 /etc/sysconfig/kube-apiserver 文件

```bash
# configure file for kube-apiserver

# --etcd-servers
ETCD_SERVERS='--etcd-servers=http://10.11.151.97:4012,http://10.11.151.100:4012,http://10.11.151.101:4012'
# --log-dir
LOG_DIR='/opt/domeos/openxxs/k8s-1.1.3-flannel/logs'
# --service-cluster-ip-range
SERVICE_CLUSTER_IP_RANGE='--service-cluster-ip-range=172.16.0.0/16'
# --insecure-bind-address
INSECURE_BIND_ADDRESS='--insecure-bind-address=0.0.0.0'
# --insecure-port
INSECURE_PORT='--insecure-port=8080'
# --bind-address
BIND_ADDRESS='--bind-address=0.0.0.0'
# --secure-port
SECURE_PORT='--secure-port=6443'
# --authorization-mode
AUTHORIZATION_MODE='--authorization-mode=ABAC'
# --authorization-policy-file
AUTHORIZATION_FILE='--authorization-policy-file=/opt/domeos/openxxs/k8s-1.1.3-flannel/authorization'
# --basic-auth-file
BASIC_AUTH_FILE='--basic-auth-file=/opt/domeos/openxxs/k8s-1.1.3-flannel/authentication.csv'
# other parameters
KUBE_APISERVER_OPTS=''
```
## 创建kube-service
/lib/systemd/system/kube-controller.service 文件

```bash
[Unit]
Description=kube-controller-manager
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-controller
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/kube-controller-manager $KUBE_MASTER \
          $LOG_DIR \
          $CLOUD_PROVIDER \
          $KUBE_CONTROLLER_OPTS
Restart=on-failure
```
## 设置kube-contr配置文件
/etc/sysconfig/kube-controller 文件

```bash
# configure file for kube-controller-manager

# --master
KUBE_MASTER='--master=http://10.11.151.97:8080'
# --log-dir
LOG_DIR='--log-dir=/opt/domeos/openxxs/k8s-1.1.3-flannel/logs'
# --cloud-provider
CLOUD_PROVIDER='--cloud-provider='
# other parameters
KUBE_CONTROLLER_OPTS=''
```
## 创建kube-sch.Service
/lib/systemd/system/kube-scheduler.service 文件

```bash
[Unit]
Description=kube-scheduler
After=kube-apiserver.service
Wants=kube-apiserver.service

[Service]
EnvironmentFile=/etc/sysconfig/kube-scheduler
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/kube-scheduler $KUBE_MASTER \
          $LOG_DIR \
          $KUBE_SCHEDULER_OPTS
Restart=on-failure
```
## 设置kube-scheduler配置文件
/etc/sysconfig/kube-scheduler 文件

```bash
# configure file for kube-scheduler

# --master
KUBE_MASTER='--master=http://10.11.151.97:8080'
# --log-dir
LOG_DIR='--log-dir=/opt/domeos/openxxs/k8s-1.1.3-flannel/logs'
# other parameters
KUBE_SCHEDULER_OPTS=''
```
## 启动KubMaster
三个组件启动是有顺序，必须等kube-apiserver正常启动之后再启动kube-controller-manager然后再启动kube-scheduler。
```bash
#1.启动kube-apiserver 
systemctl daemon-reload
systemctl start kube-apiserver
# 启动完成后查看下服务状态和日志是否正常
systemctl status -l kube-apiserver
#还可以通过如下命令查看kube-apiserver是否正常，正常则返回'ok'
curl -L http://10.11.151.97:8080/healthz

#2.启动kube-controller-manager
systemctl daemon-reload
systemctl start kube-controller
# 启动完成后查看下服务状态和日志是否正常
systemctl status -l kube-controller

#3.启动kube-scheduler
systemctl daemon-reload
systemctl start kube-scheduler
# 启动完成后查看下服务状态和日志是否正常
systemctl status -l kube-scheduler
```
# 安装KubNode
## flannel配置写入Etcd
集群中flannel的可用子网段和网络包封装方式等配置信息需要提前写入ETCD中

写入ETCD中的key为 /flannel/network/config ，后面配置flannel服务时需要用到。配置项中的 Network 为整个k8s集群可用的子网段；SubnetLen为每个Node结点的子网掩码长度；Type表示封包的方式，推荐使用vxlan，此外还有udp等方式。
```bash
curl -L http://10.11.151.97:4012/v2/keys/flannel/network/config -XPUT -d value="{\"Network\":\"172.16.0.0/16\",\"SubnetLen\":25,\"Backend\":{\"Type\":\"vxlan\",\"VNI\":1}}"
```
## 安装Docker
修改配置文件 /etc/sysconfig/docker,有可能不在这个目录,可以去/etc下面找一下
```bash
#使用yum安装,或者下载源码安装docker
yum install docker
#修改docker配置文件
DOCKER_OPTS="-g /opt/domeos/openxxs/k8s-1.1.3-flannel/docker"
INSECURE_REGISTRY="--insecure-registry 10.11.150.76:5000"
```
## 安装flannel
**这里需要特别注意，如果对机子的网卡进行了一些修改，用于连接外网的网卡名比较特殊（比如机子用的是万兆网卡，网卡名即为p6p1），启动flannel时会报"Failed to get default interface: Unable to find default route"错误，<span style="color:red;">则FLANNEL_OPTIONS需要添加参数：iface=<用于连接的网卡名>。例如100机的网卡名为em1则 iface=em1；万兆网卡的网卡名为p6p1则 iface=p6p1。</span>**
    
修改配置文件 /etc/sysconfig/flanneld,有可能不在这个目录,可以去/etc下面找一下
```bash
#使用yum安装,或者下载源码安装flannel
yum install flanneld
#修改flannel配置文件
FLANNEL_ETCD="http://10.11.151.97:4012"
FLANNEL_ETCD_KEY="/flannel/network"
FLANNEL_OPTIONS="-iface=em1"
```
## 创建kube-proxy.service
/lib/systemd/system/kube-proxy.service 文件

```bash
[Unit]
Description=kube-proxy

[Service]
EnvironmentFile=/etc/sysconfig/kube-proxy
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/kube-proxy $KUBE_MASTER \
          $PROXY_MODE \
          $LOG_DIR \
          $KUBE_PROXY_OPTS
Restart=on-failure
```
## 设置kube-proxy配置文件
/etc/sysconfig/kube-proxy  文件
```bash
# configure file for kube-proxy

# --master
KUBE_MASTER='--master=http://10.11.151.97:8080'
# --proxy-mode
PROXY_MODE='--proxy-mode=iptables'
# --log-dir
LOG_DIR='--log-dir=/opt/domeos/openxxs/k8s-1.1.3-flannel/logs'
# other parameters
KUBE_PROXY_OPTS=''
```
## 创建kubelet.service
/lib/systemd/system/kubelet.service 文件

```bash
[Unit]
Description=kubelet

[Service]
EnvironmentFile=/etc/sysconfig/kubelet
ExecStart=/opt/domeos/openxxs/k8s-1.1.3-flannel/kubelet $API_SERVERS \
          $ADDRESS \
          $HOSTNAME_OVERRIDE \
          $ALLOW_PRIVILEGED \
          $POD_INFRA \
          $CLUSTER_DNS \
          $CLUSTER_DOMAIN \
          $MAX_PODS \
          $LOG_DIR \
          $KUBELET_OPTS
Restart=on-failure
```
## 设置kubelet配置文件
/etc/sysconfig/kubelet 文件

```bash
# configure file for kubelet

# --api-servers
API_SERVERS='--api-servers=http://10.11.151.97:8080'
# --address
ADDRESS='--address=0.0.0.0'
# --hostname-override
HOSTNAME_OVERRIDE=''
# --allow-privileged
ALLOW_PRIVILEGED='--allow-privileged=false'
# --pod-infra-container-image
POD_INFRA='--pod-infra-container-image=10.11.150.76:5000/kubernetes/pause:latest'
# --cluster-dns
CLUSTER_DNS='--cluster-dns=172.16.40.1'
# --cluster-domain
CLUSTER_DOMAIN='--cluster-domain=domeos.sohu'
# --max-pods
MAX_PODS='--max-pods=70'
# --log-dir
LOG_DIR='--log-dir=/opt/domeos/openxxs/k8s-1.1.3-flannel/logs'
# other parameters
KUBELET_OPTS=''
```
这里的 CLUSTER_DNS 和 CLUSTER_DOMAIN 两项设置与集群内使用的DNS相关，具体参考《在k8s中搭建可解析hostname的DNS服务》。每个pod启动时都要先启动一个/kubernetes/pause:latest容器来进行一些基本的初始化工作，该镜像默认下载地址为 gcr.io/google_containers/pause:latest，可通过POD_INFRA参数来更改下载地址。由于GWF的存在可能会连接不上该资源，所以可以将该镜像下载下来之后再push到自己的docker本地仓库中，启动 kubelet 时从本地仓库中读取即可。MAX_PODS参数表示一个节点最多可启动的pod数量。
## 启动Kubernetes Node
### 启动flanneld
```bash
systemctl daemon-reload
systemctl start flanneld
systemctl status -l flanneld
```
### 启动Docker
```bash
systemctl daemon-reload
systemctl start docker
systemctl status -l docker
```
### 查看Docker是否被Flannel托管
```bash
#命令
ps aux | grep docker
#显示结果
/usr/bin/docke daemon -g /opt/domeos/openxxs/k8s-1.1.3-flannel/docker --bip=172.16.17.129/25 --ip-masq=true --mtu=1450 --insecure-registry 10.11.150.76:5000
#可以看到docker启动后被加上了flanneld的相关配置项了（bip, ip-masq 和 mtu）
#如果在主机上进行了多次k8s的配置，则需要对网卡进行清理。未启动flanneld和docker服务的情形下，通过 ifconfig 查看网卡，如果存在docker0、flannel.0或flannel.1
#使用如下命令进行删除
ip link delete docker0
ip link delete flannel.1
#如果没有出现(bip,ip-masq,mtu)则需要对网卡进行清理,并重新启动flanneld和docker
```
### 启动kube-proxy
```bash
systemctl daemon-reload
systemctl start kube-proxy
systemctl status -l kube-proxy
```
### 启动kubelet
```bash
systemctl daemon-reload
systemctl start kubelet
systemctl status -l kubelet
```
# 测试Kubernetes
## 查看主机状态
```bash
./kubectl --server=10.11.151.97:8080 get nodes
#返回：
NAME         LABELS                              STATUS    AGE
tc-151-100   kubernetes.io/hostname=tc-151-100   Ready     9m
tc-151-101   kubernetes.io/hostname=tc-151-101   Ready     17h
#说明：结点状态为Ready，说明100和101成功注册进k8s集群中
```
## 创建pod
创建test.yaml文件，内容如下
```bash
apiVersion: v1
kind: ReplicationController
metadata:
    name: test-1
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-1
    spec:
      containers:
        - name: iperf
          image: 10.11.150.76:5000/openxxs/iperf:1.2
      nodeSelector:
        kubernetes.io/hostname: tc-151-100
---
apiVersion: v1
kind: ReplicationController
metadata:
    name: test-2
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-2
    spec:
      containers:
        - name: iperf
          image: 10.11.150.76:5000/openxxs/iperf:1.2
      nodeSelector:
        kubernetes.io/hostname: tc-151-100
---
apiVersion: v1
kind: ReplicationController
metadata:
    name: test-3
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-3
    spec:
      containers:
        - name: iperf
          image: 10.11.150.76:5000/openxxs/iperf:1.2
      nodeSelector:
        kubernetes.io/hostname: tc-151-101
---
apiVersion: v1
kind: ReplicationController
metadata:
    name: test-4
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-4
    spec:
      containers:
        - name: iperf
          image: 10.11.150.76:5000/openxxs/iperf:1.2
      nodeSelector:
        kubernetes.io/hostname: tc-151-101
```
通过kubectl和test.yaml创建pod
```bash
./kubectl --server=10.11.151.97:8080 create -f test.yaml 
#返回：
replicationcontroller "test-1" created
replicationcontroller "test-2" created
replicationcontroller "test-3" created
replicationcontroller "test-4" created
#说明：四个rc创建成功

./kubectl --server=10.11.151.97:8080 get pods
#返回：
NAME           READY       STATUS        RESTARTS      AGE
test-1-vrt0s    1/1        Running          0          8m
test-2-uwtj7    1/1        Running          0          8m
test-3-59562    1/1        Running          0          8m
test-4-m2rqw    1/1        Running          0          8m
#说明：四个pod成功启动状态正常
```
获取四个pod对应container的IP地址
```bash
./kubectl --server=10.11.151.97:8080 describe pod test-1-vrt0s
#返回：
#......
IP     172.16.42.4
#......
#说明：该命令返回pod的详细信息，其中的IP字段即为该pod在集群内的IP地址，也是container的IP地址
```