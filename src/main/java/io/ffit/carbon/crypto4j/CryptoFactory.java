package io.ffit.carbon.crypto4j;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.security.*;

/**
 * Crypto Factory
 *
 * @author Lay
 * @date 2022/10/11
 */
public class CryptoFactory {
    public static final BouncyCastleProvider BOUNCY_CASTLE = new BouncyCastleProvider();

    public static MessageDigest digestOf(String algorithm) {
        try {
            return MessageDigest.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Mac macOf(String algorithm) {
        try {
            return Mac.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Cipher cipherOf(String algorithm) {
        try {
            return Cipher.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyFactory keyFactoryOf(String algorithm) {
        try {
            return KeyFactory.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyPairGenerator keyPairGeneratorOf(String algorithm) {
        try {
            return KeyPairGenerator.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static Signature signatureOf(String algorithm) {
        try {
            return Signature.getInstance(algorithm, BOUNCY_CASTLE);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
