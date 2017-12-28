title: GoogleChrome扩展开发
author: DuanEnJian
tags:
  - 其他
categories:
  - 其他
date: 2017-12-28 16:32:00
---
扩展程序允许您为 Chrome 浏览器增加功能，而不需要深入研究本机代码。您可以使用您在网页开发中已经很熟悉的核心技术（HTML、CSS 与 JavaScript）为 Chrome 浏览器创建新的扩展程序。如果您曾经编写过网页，您应该很快熟悉扩展程序的开发。
<!-- more -->
# 清单文件manifest.json
```json
{
    "name": "GankTools",
    "version": "1.0",
    "manifest_version": 2,
    "description": "GankTools,DuanEnJian专用笔记工具",
    "background": {
        "scripts": [ "js/background.js" ]
    },
    "browser_action": {
        "default_title": "GankTools",
        "default_icon": "ganktools.png",
        "default_popup": "index.html"
    },
    "icons": {
      "128": "ganktools.png",
      "48": "ganktools.png",
      "16": "ganktools.png"
    },
    "permissions": [ "contextMenus", "tabs", "http://*/*", "https://*/*", "notifications", "webRequest", "webRequestBlocking" ]
}
```
# API列表
1. chrome.* API https://crxdoc-zh.appspot.com/extensions/api_index
2. 扩展架构说明 https://crxdoc-zh.appspot.com/extensions/overview

# 说明
>3.1 目录结构

{% asset_img b711aa38d0071922f0b644c862e65608.png 文件清单 %}
>3.2 开发方式

{% asset_img 4eda93d97958f2a6d45b345b175d5edd.png 开发 %}
>3.3 效果预览

{% asset_img 90356a87e0e87303642372c3f8093ed6.png 效果预览 %}
>3.4 打包加载

{% asset_img df2c981f4552df9c938a6138080161ce.png 打包加载 %}
# 源码
[GankTools.Chrome.Source.tar.gz](GankTools.Chrome.Source.tar.gz)
