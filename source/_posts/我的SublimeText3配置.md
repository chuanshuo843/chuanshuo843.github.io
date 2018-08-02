---
title: 我的SublimeText3配置
author: DuanEnJian
tags:
  - 其他
categories:
  - 其他
abbrlink: 4192108374
date: 2017-12-28 16:25:00
---
Sublime Text 是一个代码编辑器（Sublime Text 2是收费软件，但可以无限期试用），也是HTML和散文先进的文本编辑器。Sublime Text是由程序员Jon Skinner于2008年1月份所开发出来，它最初被设计为一个具有丰富扩展功能的Vim。
Sublime Text具有漂亮的用户界面和强大的功能，例如代码缩略图，Python的插件，代码段等。还可自定义键绑定，菜单和工具栏。Sublime Text 的主要功能包括：拼写检查，书签，完整的 Python API ， Goto 功能，即时项目切换，多选择，多窗口等等。Sublime Text 是一个跨平台的编辑器，同时支持Windows、Linux、Mac OS X等操作系统。
<!-- more -->
# Package Control安装
Sublime 3版本
```python
import urllib.request,os,hashlib; h = 'eb2297e1a458f27d836c04bb0cbaf282' + 'd0e7a3098092775ccb37ca9d6b2e4b7d'; pf = 'Package Control.sublime-package'; ipp = sublime.installed_packages_path(); urllib.request.install_opener( urllib.request.build_opener( urllib.request.ProxyHandler()) ); by = urllib.request.urlopen( 'http://packagecontrol.io/' + pf.replace(' ', '%20')).read(); dh = hashlib.sha256(by).hexdigest(); print('Error validating download (got %s instead of %s), please try manual install' % (dh, h)) if dh != h else open(os.path.join( ipp, pf), 'wb' ).write(by)
```
# 主题安装
我们先需要通过COMMAND+SHIFT+P（如果我们是WIN系统，那就输入CTRL+SHIFT+P），调出输入框，然后我们先输入Install Package回车，然后我们再输入itg.flat就可以看到插件，然后选择回车自动安装。

{% asset_img ae0996cca2f820a9cef58b7b781ea667.jpeg step_01 %}
{% asset_img 474079d85b1012caa8170d485467aa4a.jpg step_02 %}
# 主题配置
Perferences -> Settings User
```config
{
	"color_scheme": "Packages/Theme - itg.flat/itg.dark.tmTheme",
	"theme": "itg.flat.dark.sublime-theme",
	"itg_small_tabs": true,
	"itg_sidebar_tree_small": true,
	"itg_sidebar_tree_medium": true,
	"itg_scrollbar_small": true,
	
	"font_size": 12,
	"tab_size": 4,
	"auto_indent": true,
	"smart_indent": true,
	"auto_match_enabled": true,
	"highlight_line": true,
	"translate_tabs_to_spaces": true,
	"match_brackets": true,
	"save_on_focus_lost": true,
	"auto_complete": true,
	"highlight_modified_tabs": true,
	"remember_open_files": false,
	"ignored_packages":
	[
		"Vintage"
	]
}
```
# 键盘配置
Preferences -> Key bindings - User 
```config
[
    /**
     * 常用快捷键(Sublime默认)
     * --------------
     * 
     * 光标一个单词一个单词的移动
     * { "keys": ["ctrl+left"], "command": "move", "args": {"by": "words", "forward": false} },
     * 按住shift来选文字时, 一个个单词的选而不是一个个字母
     * { "keys": ["ctrl+shift+left"], "command": "move", "args": {"by": "words", "forward": false, "extend": true} },
     *
     * 类似光标一个个单词的移动
     * { "keys": ["alt+left"], "command": "move", "args": {"by": "subwords", "forward": false} },
     * { "keys": ["alt+shift+right"], "command": "move", "args": {"by": "subword_ends", "forward": true, "extend": true} },
     *
     * 缩进
     * { "keys": ["ctrl+]"], "command": "indent" },
     * { "keys": ["ctrl+["], "command": "unindent" },
     *
     * 删除整个单词
     * { "keys": ["ctrl+backspace"], "command": "delete_word", "args": { "forward": false } },
     * { "keys": ["ctrl+delete"], "command": "delete_word", "args": { "forward": true } },
     *
     * 行排序(例如选中几个JSON字段, 让这些字段名按字母顺序排序)
     * { "keys": ["f9"], "command": "sort_lines", "args": {"case_sensitive": false} },
     *
     * 参考
     * ----------------------
     * Using Sublime Text as your IDE
     * http://www.chromium.org/developers/sublime-text
     *
     * Web Development With Sublime Text 2
     * http://www.paulund.co.uk/web-development-with-sublime-text-2
     */

    // editor配置
    { "keys": ["ctrl+v"], "command": "paste_and_indent" },
    { "keys": ["ctrl+shift+v"], "command": "paste" },

    /**
     * 适配eclipse快捷键
     *
     * 下面这位仁兄早就有了这个想法
     * Eclipse shortcuts for Sublime Text 2
     * http://icoloma.blogspot.com/2011/10/eclipse-shortcuts-for-sublime-text-2.html
     */
    { "keys": ["alt+/"], "command": "auto_complete" },
    { "keys": ["ctrl+i"], "command": "reindent" },
    // 当前行和下面一行交互位置
    { "keys": ["alt+up"], "command": "swap_line_up" },
    { "keys": ["alt+down"], "command": "swap_line_down" },
    // 复制当前行到上一行
    { "keys": ["ctrl+alt+up"], "command": "duplicate_line" },
    // 复制当前行到下一行
    { "keys": ["ctrl+alt+down"], "command": "duplicate_line" },
    // 删除整行
    { "keys": ["ctrl+d"], "command": "run_macro_file", "args": {"file": "Packages/Default/Delete Line.sublime-macro"} },
    // 光标移动到指定行
    { "keys": ["ctrl+l"], "command": "show_overlay", "args": {"overlay": "goto", "text": ":"} },
    // 快速定位到选中的文字
    { "keys": ["ctrl+k"], "command": "find_under_expand_skip" },
    // { "keys": ["ctrl+shift+x"], "command": "swap_case" },
    { "keys": ["ctrl+shift+x"], "command": "upper_case" },
    { "keys": ["ctrl+shift+y"], "command": "lower_case" },
    // 在当前行的下一行插入空行(这时鼠标可以在当前行的任一位置, 不一定是最后)
    { "keys": ["shift+enter"], "command": "run_macro_file", "args": {"file": "Packages/Default/Add Line.sublime-macro"} },
    // 定位到对于的匹配符(譬如{})(从前面定位后面时,光标要在匹配符里面,后面到前面,则反之)
    { "keys": ["ctrl+shift+p"], "command": "move_to", "args": {"to": "brackets"} },
    // 这个命令默认使用的是ctrl+shift+p
    { "keys": ["ctrl+p"], "command": "show_overlay", "args": {"overlay": "command_palette"} },
    // outline
    { "keys": ["ctrl+o"], "command": "show_overlay", "args": {"overlay": "goto", "text": "@"} },
    // 当前文件中的关键字(方便快速查找内容)
    { "keys": ["ctrl+alt+o"], "command": "show_overlay", "args": {"overlay": "goto", "text": "#"} },
    // open resource
    { "keys": ["ctrl+shift+r"], "command": "show_overlay", "args": {"overlay": "goto", "show_files": true} },
    // 文件内查找/替换
    { "keys": ["ctrl+f"], "command": "show_panel", "args": {"panel": "replace"} },
    // 全局查找/替换, 在查询结果中双击跳转到匹配位置
    {"keys": ["ctrl+h"], "command": "show_panel", "args": {"panel": "find_in_files"} },

    // plugin配置
    { "keys": ["alt+a"], "command": "alignment" },
    {"keys": ["ctrl+shift+f"], "command": "js_format"}
]
```
# 效果图
{% asset_img 38004a5d41b08848d83c87f28ce20727.jpeg 效果图 %}