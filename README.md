# VULOnceMore
漏洞复现是安全学习的基础

## 漏洞复现

> 最新or经典漏洞原理以及复现，在精不在多。

- [ ] 服务器中间件

  - [x] [Redis未授权访问主从复制RCE](https://github.com/luckyfuture0177/VULOnceMore/blob/main/%E4%B8%AD%E9%97%B4%E4%BB%B6/Redis%E6%9C%AA%E6%8E%88%E6%9D%83%E4%B8%BB%E4%BB%8E%E5%A4%8D%E5%88%B6RCE.md)
  - [ ] Docker
  - [ ] Apache Tomcat
  - [ ] Nginx
    - [ ] Nginx解析漏洞
- [ ] Java
  - [x] [Apace Shiro反序列化 550&721](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/CVE-2016-4437shiro-550%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C.md)
    - [x] [shiro550爆破key原理](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/Shiro550%E7%88%86%E7%A0%B4key%E6%96%B9%E6%B3%95.md)
  
  - [x] [FastJson反序列化远程调用注入](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/CVE-2017-18349Fastjson%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96.md)
  
  - [x] [Log4j2JNDI注入命令执行](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/CVE-2021-44228-Log4jJNDI%E6%B3%A8%E5%85%A5%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C.md)
  
  - [ ] Apache Spring
    - [x] [CVE-2022-22947 Spring Cloud Gateway Actuator API SpEL 代码注入](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/CVE-2022-22947SpringCloudGatewaySpEL%E4%BB%A3%E7%A0%81%E6%B3%A8%E5%85%A5.md)
  
  - [x] [ApacheDruid&AlibabaDruid](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/ApacheDruid%26AlibabaDruid.md)
  
  - [ ] [WebLogic历史漏洞 未完](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Java%E6%A1%86%E6%9E%B6/Weblogic%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0.md)
    - [ ] Weblogic SSRF
  
  - [ ] Apache Struts2
  
- [ ] PHP
  - [x] [phpmyadmin4.8.1文件包含漏洞CVE-2018-12613](https://github.com/luckyfuture0177/VULOnceMore/blob/main/PHP%E6%A1%86%E6%9E%B6/phpmyadmin4.8%E6%96%87%E4%BB%B6%E5%8C%85%E5%90%AB.md)
  - [x] [Discuz! 6.x/7.x 全局变量防御绕过漏洞](https://github.com/luckyfuture0177/VULOnceMore/blob/main/PHP%E6%A1%86%E6%9E%B6/Discuz!6.x7.x%E5%85%A8%E5%B1%80%E5%8F%98%E9%87%8F%E9%98%B2%E5%BE%A1%E7%BB%95%E8%BF%87%E6%BC%8F%E6%B4%9E.md)
  - [ ] ThinkPHP
    - [ ] ThinkPHP 2.x 任意代码执行漏洞
    - [ ] ThinkPHP5 RCE
    - [ ] ThinkPHP5 信息泄露
  - [ ] PHP反序列化
- [ ] Python
  - [x] [ssti模板注入](https://github.com/luckyfuture0177/VULOnceMore/blob/main/Python%E6%A1%86%E6%9E%B6/FlaskSSTI%E6%B3%A8%E5%85%A5.md)
- [ ] 

## 战术技巧

> 记录实战中的利用姿势，力求利用效果最大化。

- [x] [SQL注入利用总结](https://github.com/luckyfuture0177/VULOnceMore/blob/main/%E6%88%98%E6%9C%AF%E6%8A%80%E5%B7%A7/SQL%E6%B3%A8%E5%85%A5%E5%88%A9%E7%94%A8%E6%80%BB%E7%BB%93.md)
  - [x] [Sql注入各类型原理总结](https://luckyfuture.top/sqli-summary.html)
- [ ] SSRF利用总结(结合Weblogic SSRF)



---

面试三大漏洞，shiro，fastjson，log4j2属于必会内容，优先复现学习这三个漏洞

基础漏洞原理，利用手段和防护方法一定要吃透

后续继续复现影响范围广的新漏洞
