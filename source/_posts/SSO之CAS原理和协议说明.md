title: SSO之CAS原理和协议说明
author: DuanEnJian
date: 2017-12-28 14:47:19
tags:
---
当用户第一次访问应用系统1的时候，因为还没有登录，会被引导到认证系统中进行登录；根据用户提供的登录信息，认证系统进行身份校验，如果通过校验，应该返回给用户一个认证的凭据－－ticket；用户再访问别的应用的时候就会将这个ticket带上，作为自己认证的凭据，应用系统接受到请求之后会把ticket送到认证系统进行校验，检查ticket的合法性。如果通过校验，用户就可以在不用再次登录的情况下访问应用系统2和应用系统3了。
<!-- more -->
# 基础模式
1. 访问服务： SSO 客户端发送请求访问应用系统提供的服务资源。
2. 定向认证： SSO 客户端会重定向用户请求到 SSO 服务器。
3. 用户认证：用户身份认证。
4. 发放票据： SSO 服务器会产生一个随机的 Service Ticket 。
5. 验证票据： SSO 服务器验证票据 Service Ticket 的合法性，验证通过后，允许客户端访问服务。
6. 传输用户信息： SSO 服务器验证票据通过后，传输用户认证结果信息给客户端。

# 协议过程图
{% asset_img 859fbbf3cc94a0e1a1feb5f1461f3c76.jpg CAS协议过程 %}
如 上图： CAS Client 与受保护的客户端应用部署在一起，以 Filter 方式保护 Web 应用的受保护资源，过滤从客户端过来的每一个 Web 请求，同 时， CAS Client 会分析 HTTP 请求中是否包含请求 Service Ticket( ST 上图中的 Ticket) ，如果没有，则说明该用户是没有经过认证的；于是 CAS Client 会重定向用户请求到 CAS Server （ Step 2 ），并传递 Service （要访问的目的资源地址）。 Step 3 是用户认证过程，如果用户提供了正确的 Credentials ， CAS Server 随机产生一个相当长度、唯一、不可伪造的 Service Ticket ，并缓存以待将来验证，并且重定向用户到 Service 所在地址（附带刚才产生的 Service Ticket ） , 并为客户端浏览器设置一个 Ticket Granted Cookie （ TGC ） ； CAS Client 在拿到 Service 和新产生的 Ticket 过后，在 Step 5 和 Step6 中与 CAS Server 进行身份核实，以确保 Service Ticket 的合法性。

在该协议中，所有与 CAS Server 的交互均采用 SSL 协议，以确保 ST 和 TGC 的安全性。协议工作过程中会有 2 次重定向 的过程。但是 CAS Client 与 CAS Server 之间进行 Ticket 验证的过程对于用户是透明的（使用 HttpsURLConnection ）。
#请求认证时序图
{% asset_img 199544d72a1af5e0f065426e0f46abe8.gif 请求认证时序图 %}

# CAS如何实现SSO
>当用户访问另一个应用的服务再次被重定向到 CAS Server 的时候， CAS Server 会主动获到这个 TGC cookie ，然后做下面的事情：

1. 如果 User 持有 TGC 且其还没失效，那么就走基础协议图的 Step4 ，达到了 SSO 的效果；

2. 如果 TGC 失效，那么用户还是要重新认证 ( 走基础协议图的 Step3) 。

# 参考链接
[CAS单点登录原理以及debug跟踪登录流程](https://www.cnblogs.com/notDog/p/5252973.html)

[CAS实现SSO单点登录原理](http://www.open-open.com/lib/view/open1432381488005.html)

[CAS实现SSO（单点登录）](http://www.open-open.com/lib/view/open1423663190904.html)