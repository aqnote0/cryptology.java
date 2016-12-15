package com.aqnote.shared.encrypt.cert;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import com.aqnote.shared.encrypt.cert.gen.BCCertGenerator;

public class KeyStoreTest {
	
	public static KeyStoreTest test = new KeyStoreTest();

	public static void main(String[] args) {
		
		test.test();
	}
	
	public void test() {
		String alias = "aqnote.com.p12";
		char[] password = "yudao".toCharArray();
		String filePath = "/Users/madding/logs/tmp/" + alias;
		
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			PrivateKey key = keyPair.getPrivate();
			
			X509Certificate cert = BCCertGenerator.getIns().createRootCaCert(keyPair);
			Certificate[] chain = new X509Certificate[1];
			chain[0] = cert;
			
			KeyStore keyStore = KeyStore.getInstance("PKCS12");
			keyStore.load(null);
			keyStore.setCertificateEntry(alias, cert);
			keyStore.setKeyEntry(alias, key, password, chain);
	        FileOutputStream fos = new FileOutputStream(filePath);
	        keyStore.store(fos, password);
	        fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
