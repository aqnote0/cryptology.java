/**
 * @license
 * Copyright 2016 Google Inc. All rights reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.security.wycheproof;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite.SuiteClasses;

import com.google.security.wycheproof.WycheproofRunner.Fast;
import com.google.security.wycheproof.WycheproofRunner.Provider;
import com.google.security.wycheproof.WycheproofRunner.ProviderType;
import com.google.security.wycheproof.testcases.AesEaxTest;
import com.google.security.wycheproof.testcases.AesGcmTest;
import com.google.security.wycheproof.testcases.BasicTest;
import com.google.security.wycheproof.testcases.CipherInputStreamTest;
import com.google.security.wycheproof.testcases.CipherOutputStreamTest;
import com.google.security.wycheproof.testcases.DhTest;
import com.google.security.wycheproof.testcases.DhiesTest;
import com.google.security.wycheproof.testcases.DsaTest;
import com.google.security.wycheproof.testcases.EcKeyTest;
import com.google.security.wycheproof.testcases.EcdhTest;
import com.google.security.wycheproof.testcases.EcdsaTest;
import com.google.security.wycheproof.testcases.EciesTest;
import com.google.security.wycheproof.testcases.RsaEncryptionTest;
import com.google.security.wycheproof.testcases.RsaKeyTest;
import com.google.security.wycheproof.testcases.RsaSignatureTest;

/**
 * BouncyCastleTest excludes {@code @SlowTest} tests.
 */
@RunWith(WycheproofRunner.class)
@SuiteClasses({
  AesEaxTest.class,
  AesGcmTest.class,
  BasicTest.class,
  CipherInputStreamTest.class,
  CipherOutputStreamTest.class,
  DhTest.class,
  DhiesTest.class,
  DsaTest.class,
  EcKeyTest.class,
  EcdhTest.class,
  EcdsaTest.class,
  EciesTest.class,
  RsaEncryptionTest.class,
  RsaKeyTest.class,
  RsaSignatureTest.class,
})
@Provider(ProviderType.BOUNCY_CASTLE)
@Fast
public final class BouncyCastleTest {
  @BeforeClass
  public static void setUp() throws Exception {
    TestUtil.installOnlyThisProvider(new BouncyCastleProvider());
  }
}
