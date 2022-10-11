package io.ffit.carbon.crypto4j.asymmetric;

import io.ffit.carbon.crypto4j.CryptoFactory;
import io.ffit.carbon.crypto4j.exception.EncryptException;
import io.ffit.carbon.crypto4j.exception.SignException;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

/**
 * Asymmetric Crypto
 *
 * @author Lay
 * @date 2022/10/11
 */
public class AsymmetricCrypto {
    public static byte[] encrypt(String algorithm, Key key, byte[] data) {
        return crypt(algorithm, key, data, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(String algorithm, Key key, byte[] data) {
        return crypt(algorithm, key, data, Cipher.DECRYPT_MODE);
    }
    public static byte[] sign(String algorithm, PrivateKey key, byte[] data) {
        try {
            Signature signer = CryptoFactory.signatureOf(algorithm);
            signer.initSign(key);
            signer.update(data);
            return signer.sign();
        } catch (Exception e) {
            throw new SignException(algorithm, e);
        }
    }

    public static boolean verify(String algorithm, PublicKey key, byte[] data, byte[] sign) {
        try {
            Signature signer = CryptoFactory.signatureOf(algorithm);
            signer.initVerify(key);
            signer.update(data);
            return signer.verify(sign);
        } catch (Exception e) {
            throw new SignException(algorithm, e);
        }
    }

    private static byte[] crypt(String algorithm, Key key, byte[] data, int opMode) {
        try {
            Cipher cipher = CryptoFactory.cipherOf(algorithm);
            cipher.init(opMode, key);
            cipher.update(data);
            return cipher.doFinal();
        } catch (Exception e) {
            throw new EncryptException(algorithm, e);
        }
    }
}
