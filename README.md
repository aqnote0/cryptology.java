---
Title: README
Authors: "Peng Li"<aqnote@qq.com>
Date: 20200227
Keywords:
Copyright:
---

# com.aqnote.shared:cryptology

## Usage

### Self Sign Certificate Chain

证书操作工具 BC 版实现的都在：com.aqnote.shared.cryptology.cert.main

- AQRootCaMain: V3 版根 CA 签发器。用来派生其他中间证书和终端证书用
- AQClass1CaMain: Class1 的中级证书签发器。做服务器端证书签发，用 AQRootCaMain 签发的证书做根证书，用来签发其下路径证书，深度为 3
- AQClass1EndRadiusMain: Class1 下的 Radius 证书签发器。用来放在 ACL 中，做 Radius 服务证书校验
- AQClass3CaMain: Class3 的中级证书签发器。用来签发客户端使用
- AQClass3EndMain: Class3 下端证书签发器。可以签发员工证书，客户端邮件证书
- AQCRLMain: CRL 构造器

## Develop

---

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

### Update

TODO:

- add More cryptology and tools.

---

## Version

### V1.2.0

- 增加同态加密

### V1.1.0

- 支持 JDK9，避免调用 JDK 内部 API：sun._ com.sum._ jdk.\*
- 更新一套 CA 证书，见 META-INF/aqnote，老的证书移动到 META-INF/mad
- 变更包坐标：com.aqnote.shared:cryptology

### V1.0.0

- 增加证书链操作相关工具类
  - 签发根证书
  - 签发中级证书
  - 签发 radius 服务器证书
  - 签发普通端证书
  - 签发支持 vpn、radius 客户端证书
- 增加非对称密钥算法 DSA
- 增加非对称密钥算法 RSA
- 增加对称密钥算法 AES
- 增加对称密钥算法 Blowfish
- 增加对称密钥算法 DES
- 增加密钥算法工具类
  - 字节操作工具类
  - 证书工具类
  - 字节码加载器工具类
- 增加数字摘要算法 MDx
- 增加数字摘要算法 SHAx
- 增加数字摘要算法 SMx
- 增加数字摘要算法 Murmurx
