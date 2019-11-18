package com.aqnote.shared.cryptology.digest;

import com.aqnote.shared.cryptology.util.lang.ByteUtil;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import static com.aqnote.shared.cryptology.Constants.UTF_8;
import static com.aqnote.shared.cryptology.cert.constant.BCConstant.JCE_PROVIDER;
import static org.apache.commons.lang.StringUtils.isBlank;

public class MAC {
    private static final String OID_HMAC_WITH_SHA1         = PKCSObjectIdentifiers.id_hmacWithSHA1.toString();

    public final static String hmacWithSHA1(String src) {
        if (isBlank(src)) return "";
        try {
            return hmacWithSHA1(src.getBytes(UTF_8));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return "";
    }

    public final static String hmacWithSHA1(byte[] src) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(OID_HMAC_WITH_SHA1, JCE_PROVIDER);
            messageDigest.update(src);
            return new String(ByteUtil.toHexBytes(messageDigest.digest()));
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        }
        return "";
    }
}
