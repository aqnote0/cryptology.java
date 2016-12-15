/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com>
 * Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.aqnote.com/licenses/LICENSE-1.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.aqnote.shared.encrypt.cert.main.bc;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.crypto.Cipher;

import com.aqnote.shared.encrypt.ProviderUtil;

/**
 * AQMain.java desc：TODO 
 * @author madding.llp Dec 15, 2016 3:21:08 PM
 */
public class AQMain implements MainConstant {

    static {
        ProviderUtil.addBCProvider();
    }
    
    protected static void readByKeyStore(String ca, String keyPairAlias) throws Exception {
        KeyStore pkcs12Store = KeyStore.getInstance("PKCS12", JCE_PROVIDER);

        pkcs12Store.load(new FileInputStream(ca), USER_CERT_PASSWD);

        System.out.println("########## KeyStore Dump");

        for (Enumeration<?> en = pkcs12Store.aliases(); en.hasMoreElements();) {
            String alias = (String) en.nextElement();

            if (pkcs12Store.isCertificateEntry(alias)) {
                System.out.println("Certificate Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            } else if (pkcs12Store.isKeyEntry(alias)) {
                System.out.println("Key Entry: " + alias + ", Subject: "
                                   + (((X509Certificate) pkcs12Store.getCertificate(alias)).getSubjectDN()));
            }
        }
        
        System.out.println();
        
        Certificate certificate = pkcs12Store.getCertificate(keyPairAlias);
        PublicKey publicKey = certificate.getPublicKey();
        PrivateKey privateKey = (PrivateKey) pkcs12Store.getKey(keyPairAlias, USER_CERT_PASSWD);
        Cipher cipher = Cipher.getInstance(privateKey.getAlgorithm(), JCE_PROVIDER);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        String data = "123";
        byte[] encyptByte = cipher.doFinal(data.getBytes());
        
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decyptByte = cipher.doFinal(encyptByte);
        
        System.out.println(new String(decyptByte).equals(data));
        
        System.out.println();
    }
}
