### com.aqnote.shared:cryptography ###

#### develop ####
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

#### update ####

TODO:

- add More cryptography and tools.

----------------------------------------

** version 1.0.0 **

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
