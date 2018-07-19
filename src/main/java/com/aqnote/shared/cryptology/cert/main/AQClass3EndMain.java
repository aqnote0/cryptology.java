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

import org.bouncycastle.asn1.x500.X500Name;

import com.aqnote.shared.cryptology.cert.io.PKCSReader;
import com.aqnote.shared.cryptology.cert.io.PKCSWriter;
import com.aqnote.shared.cryptology.cert.gen.CertGenerator;
import com.aqnote.shared.cryptology.cert.loader.CaCertLoader;
import com.aqnote.shared.cryptology.cert.util.KeyPairUtil;
import com.aqnote.shared.cryptology.cert.util.X500NameUtil;

/**
 * 类AQClass3EndCreator.java的实现描述：证书构造器
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 6, 2013 9:23:41 PM
 */
public class AQClass3EndMain extends AQMain {

    public static final String CLASS3_END_EMPNO = CERT_DIR + "/class3end";

    public static void main(String[] args) throws Exception {
        // writeFile();

        createRadiusFromPath(new String[] { CLASS3_CA, ROOT_CA });

        readByKeyStore(CLASS3_END_EMPNO + P12_SUFFIX, "test");
    }

    protected static void writeFile() throws Exception {
        
        KeyPair pKeyPair = CaCertLoader.getClass3CaKeyPair(USER_CERT_PASSWD);

        String cn = "test";
        String email = "aqnote@qq.com";
        String title = "";// "p1|p2|p3|p4";
        X500Name subject = X500NameUtil.createClass3EndPrincipal(cn, email, title);
        
        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);

        X509Certificate endCert = CertGenerator.getIns().createClass3EndCert(subject, keyPair.getPublic(), pKeyPair);
        X509Certificate[] chain = new X509Certificate[3];
        chain[0] = endCert;
        chain[1] = CaCertLoader.getClass3CaCert();
        chain[2] = CaCertLoader.getRootCaCert();

        FileOutputStream oStream = new FileOutputStream(new File(CLASS3_END_EMPNO + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, oStream);

        System.out.println("end....");
    }

    protected static void createRadiusFromPath(String[] cafilePathArray) throws Exception {
        int length = cafilePathArray.length + 1;
        X509Certificate[] chain = new X509Certificate[length];
        for (int i = 1; i < length; i++) {
            InputStream iscert = new FileInputStream(new File(cafilePathArray[i - 1] + PEMCERT_SUFFIX));
            X509Certificate cert = PKCSReader.readCert(iscert);
            chain[i] = cert;
        }

        InputStream iskey = new FileInputStream(new File(cafilePathArray[0] + PEMKEY_SUFFIX));
        KeyPair pKeyPair = PKCSReader.readKeyPair(iskey, USER_CERT_PASSWD);

        String cn = "test";
        String email = "test@aqnote.com";
        String title = "";// "p1|p2|p3|p4";
        X500Name subject = X500NameUtil.createClass3EndPrincipal(cn, email, title);
        
        KeyPair keyPair = KeyPairUtil.generateRSAKeyPair(1024);
        X509Certificate endCert = CertGenerator.getIns().createClass3EndCert(subject, keyPair.getPublic(), pKeyPair);
        chain[0] = endCert;

        FileOutputStream ostream = new FileOutputStream(new File(CLASS3_END_EMPNO + PEMKEY_SUFFIX));
        PKCSWriter.storeKeyFile(keyPair, ostream, USER_CERT_PASSWD);

        ostream = new FileOutputStream(new File(CLASS3_END_EMPNO + PEMCERT_SUFFIX));
        PKCSWriter.storeCertFile(chain, ostream);

        ostream = new FileOutputStream(new File(CLASS3_END_EMPNO + P12_SUFFIX));
        PKCSWriter.storePKCS12File(chain, keyPair.getPrivate(), USER_CERT_PASSWD, ostream);
        ostream.close();

        System.out.println("end....");
    }

}
