/*
 * Copyright 2013-2023 "Peng Li"<aqnote@qq.com>
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
package com.aqnote.shared.cryptology.cert.main;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;

import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import com.aqnote.shared.cryptology.cert.constant.BCConstant;
import com.aqnote.shared.cryptology.cert.constant.DateConstant;
import com.aqnote.shared.cryptology.cert.io.PKCSWriter;
import com.aqnote.shared.cryptology.cert.loader.CaCertLoader;
import com.aqnote.shared.cryptology.cert.util.X500NameUtil;
import com.aqnote.shared.cryptology.cert.CertException;

/**
 * 类AQCRLMain.java的实现描述：证书吊销列表构造类
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 6, 2013 9:23:41 PM
 */
public class AQCRLMain extends AQMain {

    public static String CRL_FILE = CERT_DIR + "/aqnote.crl";

    public static void main(String[] args) {
        try {
            createCRL();
        } catch (CertException e) {
            e.printStackTrace();
        }

    }

    public static void createCRL() throws CertException {

        try {
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(X500NameUtil.createRootCaPrincipal(), new Date());
            crlBuilder.setNextUpdate(new Date(System.currentTimeMillis() + DateConstant.ONE_YEAR));
            X509CRLHolder crlHolder = crlBuilder.build(new JcaContentSignerBuilder(SHA256_RSA)
                    .setProvider(JCE_PROVIDER)
                    .build(CaCertLoader.getRootCaKeyPair(USER_CERT_PASSWD).getPrivate()));
            X509CRL crl = new JcaX509CRLConverter().setProvider(JCE_PROVIDER).getCRL(crlHolder);
            FileOutputStream fostream = new FileOutputStream(CRL_FILE);
            PKCSWriter.storeCRLFile(crl, fostream);

            ASN1Dump.dumpAsString(crlHolder.toASN1Structure());
        } catch (OperatorCreationException e) {
            throw new CertException(e);
        } catch (IOException e) {
            throw new CertException(e);
        } catch (InvalidKeyException e) {
            throw new CertException(e);
        } catch (CRLException e) {
            throw new CertException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new CertException(e);
        } catch (NoSuchProviderException e) {
            throw new CertException(e);
        } catch (SignatureException e) {
            throw new CertException(e);
        } catch (Exception e) {
            throw new CertException(e);
        }

        return;
    }
}
