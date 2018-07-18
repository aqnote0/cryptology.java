/**
 * Project: lsc-biz-seller
 * 
 * File Created at Jul 8, 2016
 * $Id$
 * 
 * Copyright 1999-2100 Alibaba.com Corporation Limited.
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * Alibaba Company. ("Confidential Information").  You shall not
 * disclose such Confidential Information and shall use it only in
 * accordance with the terms of the license agreement you entered into
 * with Alibaba.com.
 */
package com.aqnote.shared.encrypt;

import java.security.NoSuchAlgorithmException;

import com.aqnote.shared.encrypt.digest.BCrypt;

/**
 * TODO Comment of xxx 
 * @author tony.huangj 
 * 2:43:05 PM	
 *
 */
public class BcryptMain 
{
    public static void main(String[] args) throws NoSuchAlgorithmException 
    {
//        System.out.println(BCrypt.gensalt(13));
        String  originalPassword = "11111";
        String  salt = "$2a$13$ZZhIL7fU78qlwfifib493J";
        String  passwordCrypt = "$2a$13$ZZhIL7fU78qlwfifib493.RNyTRYYLLZupzaRDUSfYCuymFOAtymW";
        System.out.println(salt.length()-"$2y$13$".length());
        String generatedSecuredPasswordHash = BCrypt.hashpw(originalPassword, salt);
        System.out.println(generatedSecuredPasswordHash);
        System.err.println(passwordCrypt);
        boolean matched = BCrypt.checkpw(originalPassword, generatedSecuredPasswordHash);
        System.out.println(matched);
    }
}

