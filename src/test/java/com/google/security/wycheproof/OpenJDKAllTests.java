package com.google.security.wycheproof;

import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.testcases.AesGcmTest;
import com.google.security.wycheproof.testcases.BasicTest;
import com.google.security.wycheproof.testcases.CipherInputStreamTest;
import com.google.security.wycheproof.testcases.CipherOutputStreamTest;
import com.google.security.wycheproof.testcases.DhTest;
import com.google.security.wycheproof.testcases.DsaTest;
import com.google.security.wycheproof.testcases.EcKeyTest;
import com.google.security.wycheproof.testcases.EcdhTest;
import com.google.security.wycheproof.testcases.EcdsaTest;
import com.google.security.wycheproof.testcases.RsaEncryptionTest;
import com.google.security.wycheproof.testcases.RsaKeyTest;
import com.google.security.wycheproof.testcases.RsaSignatureTest;

/**
 * Tests for OpenJDK's providers: SunJCE, SunEC, etc.
 * OpenJDKAllTests runs all tests.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
  AesGcmTest.class,
  BasicTest.class,
  CipherInputStreamTest.class,
  CipherOutputStreamTest.class,
  DhTest.class,
  DsaTest.class,
  EcKeyTest.class,
  EcdhTest.class,
  EcdsaTest.class,
  RsaEncryptionTest.class,
  RsaKeyTest.class,
  RsaSignatureTest.class
})
@Provider(ProviderType.OPENJDK)
public final class OpenJDKAllTests {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyOpenJDKProviders();
  }
}
