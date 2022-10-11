package io.ffit.carbon.crypto4j.symmetric;

import io.ffit.carbon.crypto4j.CryptoFactory;
import io.ffit.carbon.crypto4j.exception.EncryptException;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Symmetric Crypto
 *
 * @author Lay
 * @date 2022/10/9
 */
public class SymmetricCrypto {

    public static byte[] encrypt(SymmetricAlgorithm algorithm, SymmetricMode mode, SymmetricPadding symmetricPadding, byte[] key, byte[] iv, byte[] data) {
        return encrypt(String.format("%s/%s/%s", algorithm, mode, symmetricPadding), key, iv, data);
    }

    public static byte[] decrypt(SymmetricAlgorithm algorithm, SymmetricMode mode, SymmetricPadding symmetricPadding, byte[] key, byte[] iv, byte[] data) {
        return decrypt(String.format("%s/%s/%s", algorithm, mode, symmetricPadding), key, iv, data);
    }

    public static byte[] encrypt(String algorithm, byte[] key, byte[] iv, byte[] data) {
        return crypt(algorithm, key, iv, data, Cipher.ENCRYPT_MODE);
    }

    public static byte[] decrypt(String algorithm, byte[] key, byte[] iv, byte[] data) {
        return crypt(algorithm, key, iv, data, Cipher.DECRYPT_MODE);
    }

    private static byte[] crypt(String algorithm, byte[] key, byte[] iv, byte[] data, int opMode) {
        try {
            SecretKeySpec keySpec = new SecretKeySpec(key, algorithm);
            Cipher cipher = CryptoFactory.cipherOf(algorithm);
            if (iv != null && iv.length > 0) {
                cipher.init(opMode, keySpec, new IvParameterSpec(iv));
            } else {
                cipher.init(opMode, keySpec);
            }
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new EncryptException(algorithm, e);
        }
    }
}
