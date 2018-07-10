/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt.cert.bc.main;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import com.aqnote.shared.encrypt.cert.bc.cover.PKCSReader;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSWriter;
import com.aqnote.shared.encrypt.cert.bc.gen.CertGenerator;
import com.aqnote.shared.encrypt.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.encrypt.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.encrypt.cert.bc.util.X500NameUtil;

/**
 * 类AQClass1CaCreator.java的实现描述：ca构造器
 * 
 * @author madding.lip Dec 6, 2013 9:23:41 PM
 */
public class AQClass1CaMain extends AQMain {

    public static void main(String[] args) throws Exception {
        // createNewChain();
        createNewChainWithCa(ROOT_CA);
        
        readByKeyStore(CLASS1_CA + P12_SUFFIX, X500NameUtil.DN_CLASS1_ROOT_CN);
    }

    protected static void createExistChain() throws Exception {

        X509Certificate pCert = CaCertLoader.getRootCaCert();
        KeyPair pKeyPair = CaCertLoader.getRootCaKeyPair();

        PublicKey publicKey = CaCertLoader.getClass1CaKeyPair().getPublic();
        X509Certificate middleCert = CertGenerator.getIns().createClass1CaCert(publicKey, pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = pCert;

        FileOutputStream oStream = new FileOutputStream(new File(CLASS1_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, pKeyPair.getPrivate(), USER_CERT_PASSWD, oStream);
        oStream.close();
        System.out.println("mad server ca created end....");
    }

    protected static void createNewChain() throws Exception {

        X509Certificate pCert = CaCertLoader.getRootCaCert();
        KeyPair pKeyPair = CaCertLoader.getRootCaKeyPair(USER_CERT_PASSWD);

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate middleCert = CertGenerator.getIns().createClass1CaCert(keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = pCert;

        FileOutputStream ostream = new FileOutputStream(new File(CLASS1_CA + PEMCERT_SUFFIX));
        PKCSWriter.storeCertFile(middleCert, ostream);
        
        ostream = new FileOutputStream(new File(CLASS1_CA + PEMKEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair.getPrivate(), ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(CLASS1_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("mad server ca created end....");
    }

    protected static void createNewChainWithCa(String cafilepath) throws Exception {

        InputStream iscert = new FileInputStream(new File(cafilepath + PEMCERT_SUFFIX));
        X509Certificate pCert = PKCSReader.readCert(iscert);

        InputStream iskey = new FileInputStream(new File(cafilepath + PEMKEY_SUFFIX));
        KeyPair pKeyPair = PKCSReader.readKeyPair(iskey, USER_CERT_PASSWD);

        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate middleCert = CertGenerator.getIns().createClass1CaCert(keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = middleCert;
        chain[1] = pCert;

        FileOutputStream ostream = new FileOutputStream(new File(CLASS1_CA + PEMCERT_SUFFIX));
        PKCSWriter.storeCertFile(middleCert, ostream);
        
        ostream = new FileOutputStream(new File(CLASS1_CA + PEMKEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(CLASS1_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("mad server ca created end....");
    }
}
