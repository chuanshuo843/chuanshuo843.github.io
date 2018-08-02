---
title: Golang之JWT的实现
author: DuanEnJian
tags:
  - RFC标准系列
categories:
  - 开发
abbrlink: 201619652
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

type JwtHeader struct {
	JwtHead string `json:"type"`
	JwtAlg  string `json:"alg"`
}

type JwtPayload struct {
	Iss  string `json:"iss"`  //Issuer，发行者
	Sub  string `json:"sub"`  //Subject，主题
	Aud  string `json:"aud"`  //Audience，观众
	Data string `json:"data"` //请求数据
	Exp  int64  `json:"exp"`  //Expiration time，过期时间
	Nbf  int64  `json:"nbf"`  //Not before
	Iat  int64  `json:"iat"`  //Issued at，发行时间
	Jti  int64  `json:"jti"`  //JWT ID
}

type JwtSecret struct {
	Key string `json:"key"` //秘钥
}

type Jwt struct {
	Header  JwtHeader
	Payload JwtPayload
	Secret  JwtSecret
}

//JWT 初始化
func InitJwt() *Jwt{
	jwt := &Jwt{}
	//设置Header
	jwt.Header.JwtAlg = "HS256"
	jwt.Header.JwtHead = "JWT"
	//设置Payload
	jwt.Payload.Iss = "https://www.ganktools.com"
	jwt.Payload.Sub = "https://www.ganktools.com"
	jwt.Payload.Aud = "https://www.ganktools.com"
	//设置加密秘钥
	jwt.Secret.Key = "jwt_key"
	return jwt
}

//编码JWT的Header头
func (header *JwtHeader) Encode() string {
	json_data, _ := json.Marshal(header)
	return base64.StdEncoding.EncodeToString(json_data)
}

//解码JWT的Header头
func (header *JwtHeader) Decode(data string) error {
	headerStr, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	errJson := json.Unmarshal(headerStr, header)
	if errJson != nil {
		return errJson
	}
	return nil
}

//解码payload部分
func (payload *JwtPayload) Decode(data string) error {
	payloadStr, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return err
	}
	errJson := json.Unmarshal(payloadStr, payload)
	if errJson != nil {
		return errJson
	}
	return nil
}

//编码JWT的payload部分
func (payload *JwtPayload) Encode() string {
	json_data, _ := json.Marshal(payload)
	return base64.StdEncoding.EncodeToString(json_data)
}

//JWT的secret部分加密
func (secret *JwtSecret) Signature(header, payload string) string {
	encode_jwt := header + "." + payload
	h := hmac.New(sha256.New, []byte(secret.Key))
	h.Write([]byte(encode_jwt))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

//JWT加密
func (jwt *Jwt) Encode() string {
	headerStr := jwt.Header.Encode()
	payloadStr := jwt.Payload.Encode()
	return headerStr + "." + payloadStr + "." + jwt.Secret.Signature(headerStr, payloadStr)
}

//JWT解码
func (jwt *Jwt) Decode(token string) error {
	data := strings.Split(token, ".")
	errHeader := jwt.Header.Decode(string(data[0]))
	if errHeader != nil {
		return errHeader
	}
	errPayload := jwt.Payload.Decode(string(data[1]))
	if errPayload != nil {
		return errPayload
	}
	return nil
}

//JWT检测
func (jwt *Jwt) Checkd(token string) bool {
	data := strings.Split(token, ".")
	//检测长度
	if len(data) != 3 {
		return false
	}
	//解码Token
	errDeCode := jwt.Decode(token)
	if errDeCode != nil {
		return false
	}
	//检测Hash是否一致
	secret := jwt.Secret.Signature(string(data[0]), string(data[1]))
	if secret != string(data[2]) {
		return false
	}
	//检测JWT是否过期
	if jwt.Payload.Exp <= time.Now().Unix() {
		return false
	}
	//检测什么时间之后可用
	if jwt.Payload.Nbf >= time.Now().Unix() {
		return false
	}
	return true
}

```
# Authorization

```go
package controllers

import (
	"time"
    
	"github.com/astaxie/beego"
	"github.com/chuanshuo843/12306_server/utils"
)

// User
type UserController struct {
	BaseController
}

//登录12306
func (u *UserController) Login() {
	if u.Kyfw == nil {
		u.Fail().SetMsg("获取用户数据失败").Send()
		return
	}
	verify := u.GetString("verify")
	username := u.GetString("username")
	password := u.GetString("password")
	errLogin := u.Kyfw.Login(username, password, verify)
	if errLogin != nil {
		u.Fail().SetMsg(errLogin.Error()).Send()
	}
	//生成JWT
	jwt := utils.InitJwt()
	jwt.Payload.Jti = time.Now().Unix()
	jwt.Payload.Iat = time.Now().Unix() - 30    //减30秒以防请求过快
	jwt.Payload.Nbf = time.Now().Unix() - 30    //减30秒以防请求过快
	jwt.Payload.Exp = time.Now().Unix() + 43200 //有效期十二个小时
	jwt.Payload.Data = `{"username":"` + u.Kyfw.LoginName + `"}`
	token := jwt.Encode()
	kyfws.Move(u.AppID, token)
	u.res.IsLogin = u.Kyfw.IsLogin
	reJson := map[string]string{"access_token": token}
	u.Success().SetMsg("登录成功").SetData(reJson).Send()
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
		beego.NSRouter("/auth/init", &controllers.UserController{}, "Get:InitLogin"),
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
		jwt := utils.InitJwt()
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