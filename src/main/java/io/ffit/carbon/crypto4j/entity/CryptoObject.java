package io.ffit.carbon.crypto4j.entity;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;

/**
 * Crypto Object
 *
 * @author Lay
 * @date 2022/10/9
 */
public class CryptoObject {

    private final byte[] source;

    private CryptoObject(byte[] source) {
        if (source == null) {
            source = new byte[0];
        }
        this.source = source;
    }

    public String hex() {
        return hex(false);
    }

    public String hex(boolean upperCase) {
        String s = Hex.toHexString(source);
        if (upperCase) {
            return s.toUpperCase();
        }
        return s.toLowerCase();
    }

    public String base64() {
        return Base64.toBase64String(source);
    }


    public static CryptoObject fromHex(String hex) {
        return new CryptoObject(Hex.decode(hex));
    }

    public static CryptoObject fromBase64(String base64) {
        return new CryptoObject(Base64.decode(base64));
    }

    public static CryptoObject of(byte[] bytes) {
        return new CryptoObject(bytes);
    }

    public static CryptoObject of(String str) {
        return new CryptoObject(str.getBytes(StandardCharsets.UTF_8));
    }

    public static CryptoObject empty() {
        return new CryptoObject(null);
    }
    public byte[] bytes() {
        return source;
    }

    public int length() {
        return source.length;
    }

    @Override
    public String toString() {
        return new String(source, StandardCharsets.UTF_8);
    }
}
