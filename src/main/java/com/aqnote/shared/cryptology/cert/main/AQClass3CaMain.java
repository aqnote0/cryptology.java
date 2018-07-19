/*
 * Copyright 2013-2023 "Peng Li"<aqnote@qq.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.cryptology.cert.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import com.aqnote.shared.cryptology.cert.io.PKCSReader;
import com.aqnote.shared.cryptology.cert.io.PKCSWriter;
import com.aqnote.shared.cryptology.cert.gen.CertGenerator;
import com.aqnote.shared.cryptology.cert.loader.CaCertLoader;
import com.aqnote.shared.cryptology.cert.util.KeyPairUtil;
import com.aqnote.shared.cryptology.cert.util.X500NameUtil;

/**
 * 类AQClass3CaCreator.java的实现描述：ca构造器
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 6, 2013 9:23:41 PM
 */
public class AQClass3CaMain extends AQMain {

    public static void main(String[] args) throws Exception {
        // createChainFromJar();
        createChainFromPath(ROOT_CA);

        readByKeyStore(CLASS3_CA + P12_SUFFIX, X500NameUtil.DN_CLASS3_ROOT_CN);
    }

    protected static void updateChain() throws Exception {

        X509Certificate pCert = CaCertLoader.getRootCaCert();
        KeyPair pKeyPair = CaCertLoader.getRootCaKeyPair();

        KeyPair keyPair = CaCertLoader.getClass3CaKeyPair();

        X509Certificate clientCaCert = CertGenerator.getIns().createClass3CaCert(keyPair.getPublic(), pKeyPair);
        X509Certificate[] clientCaChain = new X509Certificate[3];
        clientCaChain[0] = clientCaCert;
        clientCaChain[1] = pCert;

        FileOutputStream oStream = new FileOutputStream(new File(CLASS3_CA));
        PKCSWriter.storePKCS12File(clientCaChain, keyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("AQNote Class 3 CA Update End....");
    }

    protected static void createChainFromJar() throws Exception {

        X509Certificate pCert = CaCertLoader.getRootCaCert();
        KeyPair pKeyPair = CaCertLoader.getRootCaKeyPair(USER_CERT_PASSWD);

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate middleCert = CertGenerator.getIns().createClass3CaCert(keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = pCert;

        FileOutputStream ostream = new FileOutputStream(new File(CLASS3_CA + CRT_SUFFIX));
        PKCSWriter.storeCertFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(CLASS3_CA + KEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(CLASS3_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("AQNote Class 3 CA Generate End....");
    }

    protected static void createChainFromPath(String cafilepath) throws Exception {

        InputStream iscert = new FileInputStream(new File(cafilepath + PEMCERT_SUFFIX));
        X509Certificate pCert = PKCSReader.readCert(iscert);

        InputStream iskey = new FileInputStream(new File(cafilepath + PEMKEY_SUFFIX));
        KeyPair pKeyPair = PKCSReader.readKeyPair(iskey, USER_CERT_PASSWD);

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate middleCert = CertGenerator.getIns().createClass3CaCert(keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = pCert;

        FileOutputStream ostream = new FileOutputStream(new File(CLASS3_CA + PEMCERT_SUFFIX));
        PKCSWriter.storeCertFile(middleCert, ostream);

        ostream = new FileOutputStream(new File(CLASS3_CA + PEMKEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(CLASS3_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("AQNote Class 3 cCAa Generate End....");
    }
}
