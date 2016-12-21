/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt.util;

import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.openssl.PEMWriter;

import com.aqnote.shared.encrypt.cert.main.bc.MainConstant;

/**
 * CertUtilTest.java desc：test <code>CertUtil</code>
 * 
 * @author madding.lip May 12, 2014 10:09:15 AM
 */
public class CertUtilTest implements MainConstant {

    public static final Map<String, String> domainFileMap = new HashMap<String, String>();

    static {
        domainFileMap.put("https://www.alipay.com", "www.alipay.com");
        domainFileMap.put("https://www.taobao.com", "www.taobao.com");
    }

    public static void main(String[] args) throws MalformedURLException, FileNotFoundException {

        for (String key : domainFileMap.keySet()) {
            System.out.println(key + " " +  domainFileMap.get(key));
            Certificate[] certs = CertUtil.getServerCertList(new URL(key));
            try {
                PEMWriter pemWriter = new PEMWriter(new FileWriter(CERT_DIR + "/download/" + domainFileMap.get(key) + "_chain.pem"));
                for (Certificate cer : certs) {
                    pemWriter.writeObject(cer);
                    pemWriter.flush();
                }
                pemWriter.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

    }
}
