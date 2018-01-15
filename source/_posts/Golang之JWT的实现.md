title: Golang之JWT的实现
author: DuanEnJian
tags:
  - RFC标准系列
categories:
  - 开发
date: 2018-01-15 10:17:00
---
Json web token (JWT), 是为了在网络应用环境间传递声明而执行的一种基于JSON的开放标准（(RFC 7519).该token被设计为紧凑且安全的，特别适用于分布式站点的单点登录（SSO）场景。JWT的声明一般被用来在身份提供者和服务提供者间传递被认证的用户身份信息，以便于从资源服务器获取资源，也可以增加一些额外的其它业务逻辑所必须的声明信息，该token也可直接被用于认证，也可被加密。
<!-- more -->

# 结构

> JWT 标准的 Token 有三个部分

## header

>Header内容要用 Base64 的形式编码

```json
{
  "typ": "JWT",
  "alg": "HS256"
}
```
## playload

>playload内容同样要用Base64 编码

```json
{
	"iss":  "",  //Issuer，发行者
	"sub":  "",  //Subject，主题
	"aud":  "", //Audience，观众
	"data": "", //请求数据
	"exp":  "", //Expiration time，过期时间
	"nbf":  "", //Not before
	"iat":  "", //Issued at，发行时间
	"jti":  "", //JWT ID
}
```
## signature

> 签名部分主要和token的安全性有关，Signature的生成依赖前面两部分。
首先将Base64编码后的Header和Payload用.连接在一起

```javascript
//javascript
var encodedString = base64UrlEncode(header) + '.' + base64UrlEncode(payload);
var signature = HMACSHA256(encodedString, 'secret'); 
```
最后将这三部分用<red>.</red>连接成一个完整的字符串,构成了最终的jwt
# JWT生成

```go
package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

type _Header struct {
	JwtHead string `json:"type"`
	JwtAlg  string `json:"alg"`
}

type _Payload struct {
	Iss  string `json:"iss"`  //Issuer，发行者
	Sub  string `json:"sub"`  //Subject，主题
	Aud  string `json:"aud"`  //Audience，观众
	Data string `json:"data"` //请求数据
	Exp  int64  `json:"exp"`  //Expiration time，过期时间
	Nbf  int64  `json:"nbf"`  //Not before
	Iat  int64  `json:"iat"`  //Issued at，发行时间
	Jti  int64  `json:"jti"`  //JWT ID
}

type Jwt struct{}

var initPayload _Payload

var initHeader _Header

var secretKey string

func init() {
	//初始化秘钥
	secretKey = "jwt_key"
	//设置header头
	initHeader.JwtHead = "JWT"
	initHeader.JwtAlg = "HS256"
	//设置payload
	initPayload.Iss = "https://www.ganktools.com"
	initPayload.Sub = "https://www.ganktools.com"
	initPayload.Aud = "https://www.ganktools.com"
}

//编码JWT的Header头
func (_header *_Header) EncodeHeader() string {
	json_data, _ := json.Marshal(_header)
	return base64.StdEncoding.EncodeToString(json_data)
}

//解码JWT的Header头
func (_header *_Header) DecodeHeader(data string) bool {
	decode_header, _ := base64.StdEncoding.DecodeString(data)
	err_header := json.Unmarshal(decode_header, &_header)
	if err_header != nil {
		return false
	}
	return true
}

//编码payload部分
func (_payload *_Payload) EncodePayload() string {
	json_data, _ := json.Marshal(_payload)
	return base64.StdEncoding.EncodeToString(json_data)
}

//解码payload部分
func (_payload *_Payload) DecodePayload(data string) bool {
	decode_payload, _ := base64.StdEncoding.DecodeString(data)
	err_payload := json.Unmarshal(decode_payload, &_payload)
	if err_payload != nil {
		return false
	}
	return true
}

//JWT的secret部分加密
func signature(jwt, key string) string {
	secret := []byte(key)
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(jwt))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

//设置Issuer
func (jwt *Jwt) SetIssuer(iss string) *Jwt {
	initPayload.Iss = iss
	return jwt
}

//设置Subject
func (jwt *Jwt) SetSubject(sub string) *Jwt {
	initPayload.Sub = sub
	return jwt
}

//设置Audience
func (jwt *Jwt) SetAudience(aud string) *Jwt {
	initPayload.Aud = aud
	return jwt
}

//设置Key
func (jwt *Jwt) SetSecretKey(key string) {
	secretKey = key
}

//JWT加密
func (jwt *Jwt) Encode(exp int64, data string) string {
	current_time := time.Now().Unix()
	initPayload.Jti, initPayload.Iat, initPayload.Nbf = current_time, current_time, current_time
	initPayload.Exp = exp
	initPayload.Data = data
	encode_header := initHeader.EncodeHeader()
	encode_payload := initPayload.EncodePayload()
	encode_jwt := encode_header + "." + encode_payload
	secret := signature(encode_jwt, secretKey)
	return encode_jwt + "." + secret
}

//JWT检测
func (jwt *Jwt) Checkd(token string) bool {
	data := strings.Split(token, ".")
	//检测长度
	if len(data) != 3 {
		return false
	}
	//检测Hash是否一致
	secret := signature(string(data[0])+"."+string(data[1]), secretKey)
	if secret != string(data[2]) {
		return false
	}
	//解码Payload
	if !initPayload.DecodePayload(string(data[1])) {
		return false
	}
	//检测JWT是否过期
	if initPayload.Exp <= time.Now().Unix() {
		return false
	}
	//检测什么时间之后可用
	if initPayload.Nbf >= time.Now().Unix() {
		return false
	}
	return true
}

func (jwt *Jwt) GetData() string {
	return initPayload.Data
}
```
# Authorization

```go
package controllers

import (
	"time"
    
	"github.com/astaxie/beego"
	"github.com/chuanshuo843/12306_server/utils/kyfw"
)

var (
	kyfwUser kyfw.User
   jwt utils.Jwt
)

// User
type UserController struct {
	BaseController
}

//登录
func (u *UserController) Login() {
	// key := u.GetString("key")
	//用户登录
	err := kyfwUser.Login(u.GetString("username"),u.GetString("password"),u.GetString("verify"))
	if err != nil {
		u.Fail().SetMsg(err.Error()).Send()
	}
	//生成JWT
	jwt.SetSecretKey(beego.AppConfig.String("JwtKey"))
	token := jwt.Encode(time.Now().Unix()+100000, `{"username":"`+kyfwUser.ClientUserName+`"}`)
	reJson := map[string]string{"access_token": token}
	u.Success().SetMsg("登录成功").SetData(reJson).Send()
}
}
```

# 检测
```go
package routers

import (
	"net/http"
	"strings"

	"github.com/astaxie/beego"
	"github.com/astaxie/beego/context"
	"github.com/chuanshuo843/12306_server/controllers"
	"github.com/chuanshuo843/12306_server/utils"
)

func init() {
	ns := beego.NewNamespace("/v1",
		//登录
		beego.NSRouter("/auth/login", &controllers.UserController{}, "Post:Login"),
		beego.NSRouter("/auth/verifyCode", &controllers.UserController{}, "Get:VerifyCode"),
		//车次处理
		beego.NSNamespace("/schedule",
			beego.NSBefore(Auth),
			beego.NSInclude(
				&controllers.ScheduleController{},
			),
		),
		//站台处理
		beego.NSNamespace("/station",
			beego.NSBefore(Auth),
			beego.NSInclude(
				&controllers.StationController{},
			),
		),
		//乘客信息
		beego.NSNamespace("/passenger",
			beego.NSBefore(Auth),
			beego.NSInclude(
				&controllers.PassengerController{},
			),
		),
		//订单处理
		beego.NSNamespace("/order",
			beego.NSBefore(Auth),
			beego.NSInclude(
				&controllers.OrderController{},
			),
		),
	)
	beego.AddNamespace(ns)
}

func Auth(ctx *context.Context) {
	//只检测OPTIONS以外的请求
	if !ctx.Input.Is("OPTIONS") {
		authString := ctx.Input.Header("Authorization")
		if authString == "" {
			AllowCross(ctx)
			return
		}
		kv := strings.Split(authString, " ")
		if len(kv) != 2 || kv[0] != "Bearer" {
			AllowCross(ctx)
			return
		}
		token := kv[1]
		jwt := &utils.Jwt{}
		jwt.SetSecretKey(beego.AppConfig.String("JwtKey"))
		if !jwt.Checkd(token) {
			AllowCross(ctx)
			return
		}
	}
}

//错误返回
func AllowCross(ctx *context.Context) {
	ctx.Output.Header("Cache-Control", "no-store")
	ctx.Output.Header("Access-Control-Allow-Origin", "*")
	ctx.Output.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE,OPTIONS")
	ctx.Output.Header("Access-Control-Allow-Headers", "Authorization")
	ctx.Output.Header("WWW-Authenticate", `Bearer realm="`+beego.AppConfig.String("HostName")+`" error="Authorization" error_description="invalid Authorization"`)
	http.Error(ctx.ResponseWriter, "Unauthorized", 401)
}

```
# 参考资料
[RFC7519](https://tools.ietf.org/html/rfc7519)
[什么是 JWT -- JSON WEB TOKEN](https://www.jianshu.com/p/576dbf44b2ae)
[JSON Web Token - 在Web应用间安全地传递信息](http://blog.leapoahead.com/2015/09/06/understanding-jwt/)
[八幅漫画理解使用JSON Web Token设计单点登录系统](http://blog.leapoahead.com/2015/09/07/user-authentication-with-jwt/)