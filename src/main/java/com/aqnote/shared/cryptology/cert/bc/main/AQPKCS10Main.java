/*
 * Copyright 2013-2023 "Peng Li"<aqnote@qq.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.cryptology.cert.bc.main;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.aqnote.shared.cryptology.AQProviderUtil;
import com.aqnote.shared.cryptology.cert.bc.constant.BCConstant;
import com.aqnote.shared.cryptology.cert.bc.io.PKCSReader;
import com.aqnote.shared.cryptology.cert.bc.io.PKCSWriter;
import com.aqnote.shared.cryptology.cert.bc.gen.CertGenerator;
import com.aqnote.shared.cryptology.cert.bc.loader.CaCertLoader;
import com.aqnote.shared.cryptology.cert.bc.util.KeyPairUtil;
import com.aqnote.shared.cryptology.cert.bc.util.X500NameUtil;

/**
 * 类AQPKCS10Creaetor.java的实现描述：
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 5, 2013 10:05:31 AM
 */
public class AQPKCS10Main implements BCConstant {

    public static final String MAD_CLASS1_END_VPN = "/home/aqnote/output/aqnote_class1_end_vpn_csr_1";

    static {
        AQProviderUtil.addBCProvider();
    }

    public static void main(String[] args) throws Exception {

        createPKCS10(new X500Name("CN=madding.lip"), KeyPairUtil.generateRSAKeyPair());
        System.exit(-1);

        String result = "-----BEGIN CERTIFICATE REQUEST-----\n"
                        + "MIIBpTCCAQ4CAQAwJDEiMCAGCSqGSIb3DQEJAhYTdnBuLmFsaWJhYmEtaW5jLmNv"
                        + "bTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAynW6XgYtFH3L2Cp4p5w661Pr"
                        + "4zaOLObVi/9hhmm9oBXnnPYwkwlTLxc/ccaLMn/QDDy65Vcu6dklqubeFdtdEZiT"
                        + "zlxcBtWY5Uloa7C9WyOYdm+tzOUxghsxrnB5IEGQpx/o+JpEejnyhaA9PdnjjXR7"
                        + "6tegmstEkPfQyc3wFmkCAwEAAaBBMD8GCSqGSIb3DQEJDjEyMDAwDgYDVR0PAQH/"
                        + "BAQDAgWgMB4GA1UdEQQXMBWCE3Zwbi5hbGliYWJhLWluYy5jb20wDQYJKoZIhvcN"
                        + "AQEFBQADgYEArkq8F/yioCUP9lWqlE49ziGqCs3xlrX+jNWme6EOkreN/KYr1lCg"
                        + "vGj8V49aNURlZolo6sTFNcOr7BUceWtQnvcvKj6pwnK6Ay/zPymdd9gSixJPBmmm"
                        + "2HlMk5eGKku8RmsUFHMttPmnixrc6S4dQ2IvS7i0JVvgYGoYRXX1khQ=\n"
                        + "-----END CERTIFICATE REQUEST-----";

        result = "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + "MIIBwjCCASsCAQAwRTEjMCEGA1UEAxMaTWFkIENlcnQgU2lnbmluZyBBdXRob3Jp"
                 + "dHkxHjAcBgkqhkiG9w0BCQIWD2FsaWJhYmEtaW5jLmNvbTCBnzANBgkqhkiG9w0B"
                 + "AQEFAAOBjQAwgYkCgYEAynW6XgYtFH3L2Cp4p5w661Pr4zaOLObVi/9hhmm9oBXn"
                 + "nPYwkwlTLxc/ccaLMn/QDDy65Vcu6dklqubeFdtdEZiTzlxcBtWY5Uloa7C9WyOY"
                 + "dm+tzOUxghsxrnB5IEGQpx/o+JpEejnyhaA9PdnjjXR76tegmstEkPfQyc3wFmkC"
                 + "AwEAAaA9MDsGCSqGSIb3DQEJDjEuMCwwDgYDVR0PAQH/BAQDAgWgMBoGA1UdEQQT"
                 + "MBGCD2FsaWJhYmEtaW5jLmNvbTANBgkqhkiG9w0BAQUFAAOBgQBMsBXzyBFJYRq3"
                 + "yAskvy0mc1dMbChZhTB0QCaQ0JCHdp+K6yZOQrmyiTGiozc16gI8zTJgiT/sWMg9"
                 + "dWCnTistDODBou61UsPjPm6VjH9NZI9h2SceenIpnU4qF0RUPtE2X4pdTB7iavR0"
                 + "EqCUrKSA5CR7mGNUkUx62dV1H+PfLQ==\n" + "-----END CERTIFICATE REQUEST-----";

        result = "-----BEGIN CERTIFICATE REQUEST-----\n"
                 + "MIIBrTCCARYCAQAwKDEmMCQGCSqGSIb3DQEJAhYXYmVpamluZy12cG4uYWxpYmFi"
                 + "YS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBALe9oFa1FqWF/8gjIY1B"
                 + "vSnDxMJJF26b3mT9Z2F+iG5y3NZyL3LWF/4x5fc/zSkg2g/XXoepbylGrAXLatAk"
                 + "ilNmIXH2ZA9WsZWXa+oopsELa/Vgf1IritQyXizmOAwVYix5f2rND7IBNHw2sQz+"
                 + "s/23Jp1jRQXWQiu6Z5Se3L8lAgMBAAGgRTBDBgkqhkiG9w0BCQ4xNjA0MA4GA1Ud"
                 + "DwEB/wQEAwIFoDAiBgNVHREEGzAZghdiZWlqaW5nLXZwbi5hbGliYWJhLmNvbTAN"
                 + "BgkqhkiG9w0BAQUFAAOBgQA/+XrgyNdw85qiEC17TQpC9/DhzMDU/GetnYF71rTF"
                 + "pgdavzwCqPUDQ3d1QGRkd6fGm3YE28d+/2D3fr4FiE0pZte9BauYf8Kmn5dcwXXk"
                 + "wdKaqfwl11xiGWM2oboVlIXcWqsm86d09hLNcKXeIHrOrwR9V2+7+xUghTb3t715" + "jg==\n"
                 + "-----END CERTIFICATE REQUEST-----";
        byte[] csrByte = result.getBytes();
        InputStream istream = new ByteArrayInputStream(csrByte);
        PKCS10CertificationRequest pkcs10 = PKCSReader.readCSR(istream);
        signPKCS10(pkcs10);
    }

    public static String createPKCS10(X500Name x500Name, KeyPair keyPair) throws Exception {
        try {
            PKCS10CertificationRequest csr = CertGenerator.getIns().createCSR(x500Name, keyPair);
            FileOutputStream ostream = new FileOutputStream("/home/aqnote/output/a.p10");
            PKCSWriter.storePKCS10File(csr, ostream);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static X509Certificate signPKCS10(PKCS10CertificationRequest pkcs10) throws Exception {

        KeyPair pKeyPair = CaCertLoader.getClass1CaKeyPair(USER_CERT_PASSWD);

        X500Name issuer = X500NameUtil.createClass1CaPrincipal();

        X509Certificate signedCert = CertGenerator.getIns().signCert(pkcs10, issuer, pKeyPair);

        FileOutputStream ostream = new FileOutputStream(new File(MAD_CLASS1_END_VPN + CRT_SUFFIX));
        PKCSWriter.storeCertFile(signedCert, ostream);

        System.out.println("end....");

        return null;
    }

}
