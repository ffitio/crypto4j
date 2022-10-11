package io.ffit.carbon.crypto4j.digest;

import io.ffit.carbon.crypto4j.CryptoFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;

/**
 * Digest Crypto
 *
 * @author Lay
 * @date 2022/10/9
 */
public class DigestCrypto {

    public static byte[] digest(DigestAlgorithm algorithm, byte[] data) {
        return digest(algorithm.toString(), data);
    }

    public static byte[] digest(String algorithm, byte[] data) {
        MessageDigest digest = CryptoFactory.digestOf(algorithm);
        digest.update(data);
        return digest.digest();
    }

    public static byte[] hmac(DigestAlgorithm algorithm, byte[] key, byte[] data) {
        return hmac(String.format("Hmac%s", algorithm), key, data);
    }

    public static byte[] hmac(String algorithm, byte[] key, byte[] data) {
        try {
            Mac mac = CryptoFactory.macOf(algorithm);
            mac.init(new SecretKeySpec(key, algorithm));
            mac.update(data);
            return mac.doFinal();
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }
}
