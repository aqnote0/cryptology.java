# com.aqnote.shared:cryptology

## use|使用方法

### 证书
证书操作工具BC版实现的都在：com.aqnote.shared.cryptology.cert.bc.main
- AQRootCaMain: V3版根CA签发器。用来派生其他中间证书和终端证书用
- AQClass1CaMain: Class1的中级证书签发器。做服务器端证书签发，用AQRootCaMain签发的证书做根证书，用来签发其下路径证书，深度为3
- AQClass1EndRadiusMain: Class1下的Radius证书签发器。用来放在ACL中，做Radius服务证书校验
- AQClass3CaMain: Class3的中级证书签发器。用来签发客户端使用
- AQClass3EndMain: Class3下端证书签发器。可以签发员工证书，客户端邮件证书
- AQCRLMain: CRL构造器。
- 


## develop|开发
-------------------------------------------------------------

- install  
```bash
  mvn install -Dmaven.test.skip
```
- import into eclipse  
```bash
  mvn clean;mvn install -Dmaven.test.skip  
  mvn eclipse:eclipse
```

- code template:  
 if you want to add some tools or fix bugs,the follow path is need for you  
 [模版配置类](https://github.com/aqnotecom/java.codestyle/tree/master/eclipse/templates)

### update

TODO:

- add More cryptology and tools.

----------------------------------------

## 版本信息

### V1.1.0
- 支持JDK9，避免调用JDK内部API：sun.* com.sum.* jdk.*
- 更新一套CA证书，见META-INF/aqnote，老的证书移动到META-INF/mad
- 变更包坐标：com.aqnote.shared:cryptology
- 增加同态加密

### V1.0.0
- 增加证书链操作相关工具类
  - 签发根证书
  - 签发中级证书
  - 签发radius服务器证书
  - 签发普通端证书
  - 签发支持vpn、radius客户端证书
- 增加非对称密钥算法DSA
- 增加非对称密钥算法RSA
- 增加对称密钥算法AES
- 增加对称密钥算法Blowfish
- 增加对称密钥算法DES
- 增加密钥算法工具类
  - 字节操作工具类
  - 证书工具类
  - 字节码加载器工具类
- 增加数字摘要算法MDx
- 增加数字摘要算法SHAx
- 增加数字摘要算法SMx
- 增加数字摘要算法Murmurx
