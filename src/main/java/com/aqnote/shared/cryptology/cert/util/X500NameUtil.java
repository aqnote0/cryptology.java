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
package com.aqnote.shared.cryptology.cert.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aqnote.shared.cryptology.util.lang.MessageUtil;

/**
 * 类X500Name.java的实现描述：TODO 类实现描述
 * 
 * @author "Peng Li"<aqnote@qq.com> Dec 6, 2013 11:11:30 PM
 */
public class X500NameUtil {
    private static final Logger logger = LoggerFactory.getLogger(X500NameUtil.class);

    private static final String ISSUE_STRING       = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN=device,  Email=madding.lip@gmail.com";
    private static final String SUBJECT_Pattern    = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN={0},  Email={1}";
    private static final String SUBJECT_PatternExt = "C=CN,  ST=ZheJiang,  L=HangZhou,  O=MADDING,  OU=Inc,  CN={0},  Email={1}, T={2}";

    public static X500Name issueName          = null;

    public static X500Name getIssueName() {
        if (issueName == null) {
            issueName = new X500Name(ISSUE_STRING);
        }
        return issueName;
    }

    public static X500Name getSubjectName(String cn, String email) {
        X500Name subjectName = null;
        String subjectString = MessageUtil.formatMessage(SUBJECT_Pattern, new String[] { cn, email });
        subjectName = new X500Name(subjectString);
        return subjectName;
    }

    public static X500Name getSubjectName(String cn, String email, String title) {
        X500Name subjectName = null;
        String subjectString = MessageUtil.formatMessage(SUBJECT_PatternExt, new String[] { cn, email, title});
        subjectName = new X500Name(subjectString);
        return subjectName;
    }
}
