/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt;

import org.junit.Assert;
import junit.framework.TestCase;

import com.aqnote.shared.encrypt.digest.SHA;
import com.aqnote.shared.encrypt.symmetric.Blowfish;

/**
 * 类BlowfishTest.java的实现描述：blowfish测试
 * 
 * @author madding.lip May 8, 2012 2:18:16 PM
 */
public class BlowfishTest extends TestCase {

    Blowfish blowfish = null;

    protected void setUp() throws Exception {
        String salt = "$2y$04$ZZhIL7fU78qlwfifib493J";

        blowfish = new Blowfish("ZZhIL7fU78qlwfifib493J", new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
    }

    public void testEncrypt() {
        String data = "11111";
        String sData = blowfish.encrypt(data);
        for (int i = 0; i < 16; i++) {
            sData = SHA.sha1(sData.getBytes());
        }
        System.out.println(sData);
        data = blowfish.decrypt(sData);
        System.out.println(data);
    }
    // RNyTRYYLLZupzaRDUSfYCuymFOAtymW

    public void testDecrypt() {
        System.out.println(blowfish.decrypt("lo5S3AFpCSZKMYp1Z0giL8z8n4j2Hw4f"));
        Assert.assertEquals("abasd中文1234!@#$", blowfish.decrypt("lo5S3AFpCSZKMYp1Z0giL8z8n4j2Hw4f"));
    }
}
