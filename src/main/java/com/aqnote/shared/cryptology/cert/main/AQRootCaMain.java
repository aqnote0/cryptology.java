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
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import com.aqnote.shared.cryptology.cert.io.PKCSWriter;
import com.aqnote.shared.cryptology.cert.gen.CertGenerator;
import com.aqnote.shared.cryptology.cert.loader.CaCertLoader;
import com.aqnote.shared.cryptology.cert.util.KeyPairUtil;
import com.aqnote.shared.cryptology.cert.util.X500NameUtil;

/**
 * 类AQRootCaCreator.java的实现描述：
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 6, 2013 9:23:41 PM
 */
public class AQRootCaMain extends AQMain {

    public static void main(String[] args) throws Exception {
        // updateChain();
        createChain();
        readByKeyStore(ROOT_CA + P12_SUFFIX, X500NameUtil.DN_ROOT_CN);
    }

    protected static void updateChain() throws Exception {

        long start = System.currentTimeMillis();
        System.out.println("AQNote Root CA Update Start....");
        KeyPair keyPair = CaCertLoader.getRootCaKeyPair();
        X509Certificate cert = CertGenerator.getIns().createRootCaCert(keyPair);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        FileOutputStream fos = new FileOutputStream(new File(ROOT_CA));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, fos);
        fos.close();
        long end = System.currentTimeMillis();
        System.out.println("AQNote Root CA Update End...." + (end - start));
    }

    protected static void createChain() throws Exception {
        
        long start = System.currentTimeMillis();
        System.out.println("AQNote Root CA Generate Start....");
        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate cert = CertGenerator.getIns().createRootCaCert(keyPair);
        X509Certificate[] chain = new X509Certificate[1];
        chain[0] = cert;

        FileOutputStream ostream = new FileOutputStream(new File(ROOT_CA + PEMCERT_SUFFIX));
        PKCSWriter.storeCertFile(chain, ostream);
        
        ostream = new FileOutputStream(new File(ROOT_CA + PEMKEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(ROOT_CA + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();
        long end = System.currentTimeMillis();
        System.out.println("AQNote Root cCAa Generate End...." + (end - start));
    }

}
