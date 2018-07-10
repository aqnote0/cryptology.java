/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt;

import org.apache.commons.codec.digest.Crypt;

import com.aqnote.shared.encrypt.digest.JCrypt;

/**
 * Snippet.java desc：TODO
 * 
 * @author madding.lip Jun 23, 2016 11:33:19 PM
 */
public class Snippet {

    public static void main(String arg[]) {

        String result = JCrypt.crypt("$2a$13$ZZhIL7fU78qlwfifib493J", "11111");
        System.out.println(result);
        // $2y$13$ZZhIL7fU78qlwfifib493.RNyTRYYLLZupzaRDUSfYCuymFOAtymW
        result = Crypt.crypt("11111".getBytes(), "$2a$13$ZZhIL7fU78qlwfifib493J");
        System.out.println(result);
    }
}
