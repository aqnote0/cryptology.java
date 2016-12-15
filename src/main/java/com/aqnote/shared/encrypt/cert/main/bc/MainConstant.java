/*
 * Copyright 2013-2023 Peng Li <madding.lip@gmail.com> Licensed under the AQNote License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy of the License at
 * http://www.aqnote.com/licenses/LICENSE-1.0 Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific language governing permissions and limitations under the
 * License.
 */
package com.aqnote.shared.encrypt.cert.main.bc;

import com.aqnote.shared.encrypt.cert.bc.constant.BCConstant;

/**
 * MainBCConstant.java desc：TODO
 * 
 * @author madding.lip Dec 15, 2016 1:41:16 PM
 */
public interface MainConstant extends BCConstant {

    public static String       CERT_DIR       = "/Users/madding/logs/certificate";
    // CA
    public static final String ROOT_CA        = CERT_DIR + "/aqnote_rootca";
    // Server CA
    public static String       CLASS1_CA      = CERT_DIR + "/aqnote_class1ca";
    // Keep CA
    public static final String CLASS2_CA      = CERT_DIR + "/aqnote_class2ca";
    // Client CA
    public static final String CLASS3_CA      = CERT_DIR + "/aqnote_class3ca";

    public static final String PEMKEY_SUFFIX  = "_key" + PEM_SUFFIX;
    public static final String PEMCERT_SUFFIX = "_cert" + PEM_SUFFIX;

}
