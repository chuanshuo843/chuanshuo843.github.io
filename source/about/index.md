title: 关于
type: about
comments: false
date: 2017-12-27 15:23:40
keywords: o时过境迁心难沉,简历,个人资料
description: o时过境迁心难沉的个人资料
---
<script>
    window.onload = function(){
        if(/Android|webOS|iPhone|iPod|BlackBerry/i.test(navigator.userAgent)) {
            window.location.href="https://github.com/chuanshuo843/resume/blob/master/%E6%AE%B5%E6%81%A9%E5%BB%BA-PHP%E9%AB%98%E7%BA%A7%E5%B7%A5%E7%A8%8B%E5%B8%88.pdf";
        } else {
            document.getElementsByTagName('embed')[0].setAttribute('height',1330);
            document.getElementsByClassName('post-description')[0].style.cssText = "display:none;";
            var head = document.getElementsByClassName('post-header');
            head[0].parentNode.removeChild(head[0]);
        }
    }
</script>
{% pdf ./段恩建-PHP高级工程师.pdf %}
