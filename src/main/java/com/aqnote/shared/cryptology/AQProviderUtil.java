/*
 * Copyright 2013-2023 "Peng Li"<aqnote@qq.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.cryptology;

import java.security.Provider;
import java.security.Security;

import com.aqnote.shared.cryptology.util.ProviderUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.aqnote.shared.cryptology.cert.constant.BCConstant;

/**
 * Provider.java desc：TODO
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 23, 2015 5:42:52 PM
 */
public class AQProviderUtil {

    public static void addBCProvider() {
        Provider bcProvider = Security.getProvider(BCConstant.JCE_PROVIDER);
        if (bcProvider == null) {
            Security.insertProviderAt(new BouncyCastleProvider(), 1);
        }
    }

    public static void resetToBCProvider() {
        ProviderUtil.removeAllProvider();
        Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }

    public static void resetToOpenJDKProviders() throws Exception {
        ProviderUtil.removeAllProvider();
        ProviderUtil.addProvider("com.sun.net.ssl.internal.ssl.Provider");
        ProviderUtil.addProvider("com.sun.crypto.provider.SunJCE");
        ProviderUtil.addProvider("com.sun.security.sasl.Provider");
        ProviderUtil.addProvider("org.jcp.xml.dsig.internal.dom.XMLDSigRI");
        ProviderUtil.addProvider("sun.security.ec.SunEC");
        ProviderUtil.addProvider("sun.security.jgss.SunProvider");
        ProviderUtil.addProvider("sun.security.provider.Sun");
        ProviderUtil.addProvider("sun.security.rsa.SunRsaSign");
        ProviderUtil.addProvider("sun.security.smartcardio.SunPCSC");
    }

}
