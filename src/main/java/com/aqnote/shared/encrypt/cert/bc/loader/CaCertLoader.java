/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt.cert.bc.loader;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;

import com.aqnote.shared.encrypt.ProviderUtil;
import com.aqnote.shared.encrypt.cert.bc.cover.PKCSReader;
import com.aqnote.shared.encrypt.util.lang.ClassLoaderUtil;
import com.aqnote.shared.encrypt.util.lang.StreamUtil;

/**
 * 类CaCertLoader.java的实现描述：ca文件到内存持久化工具类
 * 
 * @author madding.lip Dec 6, 2013 9:30:09 PM
 */
public class CaCertLoader {

    static {
        ProviderUtil.addBCProvider();
    }

    private static final String    CA_Cert_FILE         = "META-INF/aqnote/root_ca_cert.pem";
    private static final String    CA_KEY_FILE          = "META-INF/aqnote/root_ca_key.pem";
    private static final String    CLASS1_CA_Cert_FILE  = "META-INF/aqnote/class1_ca_cert.pem";
    private static final String    CLASS1_CA_KEY_FILE   = "META-INF/aqnote/class1_ca_key.pem";
    private static final String    CLASS2_CA_Cert_FILE  = "META-INF/aqnote/class2_ca_cert.pem";
    private static final String    CLASS2_CA_KEY_FILE   = "META-INF/aqnote/class2_ca_key.pem";
    private static final String    CLASS_3_CA_Cert_FILE = "META-INF/aqnote/class3_ca_cert.pem";
    private static final String    CLASS_3_CA_KEY_FILE  = "META-INF/aqnote/class3_ca_key.pem";

    private static final String    BEGIN_CERT           = "-----BEGIN CERTIFICATE-----\n";
    private static final String    END_CERT             = "-----END CERTIFICATE-----\n";

    private static X509Certificate rootCaCert;
    private static KeyPair         rootCaKeyPair;
    private static X509Certificate class1CaCert;
    private static KeyPair         class1CaKeyPair;
    private static X509Certificate class2CaCert;
    private static KeyPair         class2CaKeyPair;
    private static X509Certificate class3RootCert;
    private static KeyPair         class3RootKeyPair;

    private static String          b64RootCaCert;

    public synchronized static X509Certificate getRootCaCert() throws IOException {
        if (rootCaCert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_Cert_FILE);
            rootCaCert = PKCSReader.readCert(is);
            is.close();
        }
        return rootCaCert;
    }

    public synchronized static String getB64RootCaCert() throws IOException {
        if (StringUtils.isBlank(b64RootCaCert)) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_Cert_FILE);
            b64RootCaCert = StreamUtil.stream2Bytes(is, StandardCharsets.UTF_8);
            b64RootCaCert = StringUtils.removeStart(b64RootCaCert, BEGIN_CERT);
            b64RootCaCert = StringUtils.removeEnd(b64RootCaCert, END_CERT);
        }
        return b64RootCaCert;
    }

    public synchronized static KeyPair getRootCaKeyPair() throws IOException {
        if (rootCaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            rootCaKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return rootCaKeyPair;
    }

    public synchronized static KeyPair getRootCaKeyPair(char[] pwd) throws IOException {
        if (rootCaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CA_KEY_FILE);
            rootCaKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return rootCaKeyPair;
    }

    public synchronized static X509Certificate getClass1CaCert() throws IOException {
        if (class1CaCert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_Cert_FILE);
            class1CaCert = PKCSReader.readCert(is);
            is.close();
        }
        return class1CaCert;
    }

    public synchronized static KeyPair getClass1CaKeyPair() throws IOException {
        if (class1CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_KEY_FILE);
            class1CaKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class1CaKeyPair;
    }

    public synchronized static KeyPair getClass1CaKeyPair(char[] pwd) throws IOException {
        if (class1CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS1_CA_KEY_FILE);
            class1CaKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class1CaKeyPair;
    }

    public synchronized static X509Certificate getClass2CaCert() throws IOException {
        if (class2CaCert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_Cert_FILE);
            class2CaCert = PKCSReader.readCert(is);
            is.close();
        }
        return class2CaCert;
    }

    public synchronized static KeyPair getClass2CaKeyPair() throws IOException {
        if (class2CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_KEY_FILE);
            class2CaKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class2CaKeyPair;
    }

    public synchronized static KeyPair getClass2CaKeyPair(char[] pwd) throws IOException {
        if (class2CaKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS2_CA_KEY_FILE);
            class2CaKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class2CaKeyPair;
    }

    public synchronized static X509Certificate getClass3CaCert() throws IOException {
        if (class3RootCert == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_Cert_FILE);
            class3RootCert = PKCSReader.readCert(is);
            is.close();
        }
        return class3RootCert;
    }

    public synchronized static KeyPair getClass3CaKeyPair() throws IOException {
        if (class3RootKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_KEY_FILE);
            class3RootKeyPair = PKCSReader.readKeyPair(is, null);
            is.close();
        }
        return class3RootKeyPair;
    }

    public synchronized static KeyPair getClass3CaKeyPair(char[] pwd) throws IOException {
        if (class3RootKeyPair == null) {
            ClassLoader classLoader = ClassLoaderUtil.getClassLoader();
            InputStream is = classLoader.getResourceAsStream(CLASS_3_CA_KEY_FILE);
            class3RootKeyPair = PKCSReader.readKeyPair(is, pwd);
            is.close();
        }
        return class3RootKeyPair;
    }

}
