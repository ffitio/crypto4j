package io.ffit.carbon.crypto4j;

import io.ffit.carbon.crypto4j.asymmetric.*;
import io.ffit.carbon.crypto4j.digest.DigestAlgorithm;
import io.ffit.carbon.crypto4j.digest.DigestCrypto;
import io.ffit.carbon.crypto4j.entity.CryptoKey;
import io.ffit.carbon.crypto4j.entity.CryptoObject;
import io.ffit.carbon.crypto4j.symmetric.SymmetricAlgorithm;
import io.ffit.carbon.crypto4j.symmetric.SymmetricCrypto;
import io.ffit.carbon.crypto4j.symmetric.SymmetricMode;
import io.ffit.carbon.crypto4j.symmetric.SymmetricPadding;

/**
 * Crypto
 *
 * @author Lay
 * @date 2022/10/9
 */
public class Crypto {

    /**
     * Digest
     */
    public static class Digest {
        /**
         * MD5 Digest
         * @param data
         * @return
         */
        public static CryptoObject md5(CryptoObject data) {
            return digest(DigestAlgorithm.MD5, data);
        }

        /**
         * SHA-1 Digest
         * @param data
         * @return
         */
        public static CryptoObject sha1(CryptoObject data) {
            return digest(DigestAlgorithm.SHA1, data);
        }

        /**
         * SHA-256 Digest
         * @param data
         * @return
         */
        public static CryptoObject sha256(CryptoObject data) {
            return digest(DigestAlgorithm.SHA_256, data);
        }

        /**
         * SHA-512 Digest
         * @param data
         * @return
         */
        public static CryptoObject sha512(CryptoObject data) {
            return digest(DigestAlgorithm.SHA_512, data);
        }

        /**
         * SM3 Digest
         * @param data
         * @return
         */
        public static CryptoObject sm3(CryptoObject data) {
            return digest(DigestAlgorithm.SM3, data);
        }

        public static CryptoObject digest(DigestAlgorithm algorithm, CryptoObject data) {
            return CryptoObject.of(DigestCrypto.digest(algorithm, data.bytes()));
        }
    }

    /**
     * HMAC
     */
    public static class HMac {
        /**
         * HMAC MD5
         * @param data
         * @return
         */
        public static CryptoObject md5(CryptoObject key, CryptoObject data) {
            return hmac(DigestAlgorithm.MD5, key, data);
        }

        /**
         * HMAC SHA-1
         * @param data
         * @return
         */
        public static CryptoObject sha1(CryptoObject key, CryptoObject data) {
            return hmac(DigestAlgorithm.SHA1, key, data);
        }

        /**
         * HMAC SHA-256
         * @param data
         * @return
         */
        public static CryptoObject sha256(CryptoObject key, CryptoObject data) {
            return hmac(DigestAlgorithm.SHA_256, key, data);
        }

        /**
         * HMAC SHA-512
         * @param data
         * @return
         */
        public static CryptoObject sha512(CryptoObject key, CryptoObject data) {
            return hmac(DigestAlgorithm.SHA_512, key, data);
        }

        /**
         * HMAC SM3
         * @param data
         * @return
         */
        public static CryptoObject sm3(CryptoObject key, CryptoObject data) {
            return hmac(DigestAlgorithm.SM3, key, data);
        }

        public static CryptoObject hmac(DigestAlgorithm algorithm, CryptoObject key, CryptoObject data) {
            return CryptoObject.of(DigestCrypto.hmac(algorithm, key.bytes(), data.bytes()));
        }
    }

    /**
     * AES
     */
    public static final Symmetric AES = new Symmetric(SymmetricAlgorithm.AES);

    /**
     * DES
     */
    public static final Symmetric DES = new Symmetric(SymmetricAlgorithm.DES);

    /**
     * SM4
     */
    public static final Symmetric SM4 = new Symmetric(SymmetricAlgorithm.SM4);

    public static class Symmetric {
        private static final SymmetricMode DEFAULT_MODE = SymmetricMode.ECB;
        private static final SymmetricPadding DEFAULT_PADDING = SymmetricPadding.PKCS5Padding;
        private final SymmetricAlgorithm algorithm;

        private Symmetric(SymmetricAlgorithm algorithm) {
            this.algorithm = algorithm;
        }

        public CryptoObject encrypt(CryptoObject key, CryptoObject data) {
            return encrypt(DEFAULT_MODE, DEFAULT_PADDING, key, data);
        }

        public CryptoObject decrypt(CryptoObject key, CryptoObject data) {
            return decrypt(DEFAULT_MODE, DEFAULT_PADDING, key, data);
        }

        public CryptoObject encrypt(SymmetricMode mode, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return encrypt(mode, DEFAULT_PADDING, key, iv, data);
        }

        public CryptoObject decrypt(SymmetricMode mode, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return decrypt(mode, DEFAULT_PADDING, key, iv, data);
        }

        public CryptoObject encrypt(SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject data) {
            return encrypt(mode, padding, key, CryptoObject.empty(), data);
        }

        public CryptoObject decrypt(SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject data) {
            return decrypt(mode, padding, key, CryptoObject.empty(), data);
        }

        public CryptoObject encrypt(SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return encrypt(algorithm, mode, padding, key, iv, data);
        }

        public CryptoObject decrypt(SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return decrypt(algorithm, mode, padding, key, iv, data);
        }

        public static CryptoObject encrypt(SymmetricAlgorithm algorithm, SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return CryptoObject.of(SymmetricCrypto.encrypt(algorithm, mode, padding, key.bytes(), iv.bytes(), data.bytes()));
        }

        public static CryptoObject decrypt(SymmetricAlgorithm algorithm, SymmetricMode mode, SymmetricPadding padding, CryptoObject key, CryptoObject iv, CryptoObject data) {
            return CryptoObject.of(SymmetricCrypto.decrypt(algorithm, mode, padding, key.bytes(), iv.bytes(), data.bytes()));
        }
    }

    /**
     * RSA
     */
    public static class RSA {
        private static final AsymmetricAlgorithm ALGORITHM = AsymmetricAlgorithm.RSA;
        private static final RSAMode DEFAULT_MODE = RSAMode.None;
        private static final RSAPadding DEFAULT_PADDING = RSAPadding.NoPadding;

        public static CryptoObject encryptWithPublicKey(CryptoKey publicKey, CryptoObject data) {
            return encryptWithPublicKey(DEFAULT_MODE, DEFAULT_PADDING, publicKey, data);
        }

        public static CryptoObject encryptWithPrivateKey(CryptoKey privateKey, CryptoObject data) {
            return encryptWithPrivateKey(DEFAULT_MODE, DEFAULT_PADDING, privateKey, data);
        }

        public static CryptoObject decryptWithPublicKey(CryptoKey publicKey, CryptoObject data) {
            return decryptWithPublicKey(DEFAULT_MODE, DEFAULT_PADDING, publicKey, data);
        }

        public static CryptoObject decryptWithPrivateKey(CryptoKey privateKey, CryptoObject data) {
            return decryptWithPrivateKey(DEFAULT_MODE, DEFAULT_PADDING, privateKey, data);
        }

        public static CryptoObject encryptWithPublicKey(RSAMode mode, RSAPadding padding, CryptoKey publicKey, CryptoObject data) {
            return Asymmetric.encryptWithPublicKey(String.format("%s/%s/%s", ALGORITHM, mode, padding), publicKey, data);
        }

        public static CryptoObject encryptWithPrivateKey(RSAMode mode, RSAPadding padding,CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.encryptWithPrivateKey(String.format("%s/%s/%s", ALGORITHM, mode, padding), privateKey, data);
        }

        public static CryptoObject decryptWithPublicKey(RSAMode mode, RSAPadding padding,CryptoKey publicKey, CryptoObject data) {
            return Asymmetric.decryptWithPublicKey(String.format("%s/%s/%s", ALGORITHM, mode, padding), publicKey, data);
        }

        public static CryptoObject decryptWithPrivateKey(RSAMode mode, RSAPadding padding,CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.decryptWithPrivateKey(String.format("%s/%s/%s", ALGORITHM, mode, padding), privateKey, data);
        }

        public static CryptoObject sign(RSASignAlgorithm algorithm, CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.sign(algorithm.toString(), privateKey, data);
        }

        public static boolean verify(RSASignAlgorithm algorithm, CryptoKey publicKey, CryptoObject data, CryptoObject sign) {
            return Asymmetric.verify(algorithm.toString(), publicKey, data, sign);
        }
    }

    /**
     * SM2
     */
    public static class SM2 {
        private static final AsymmetricAlgorithm algorithm = AsymmetricAlgorithm.SM2;

        public static CryptoObject encryptWithPublicKey(CryptoKey publicKey, CryptoObject data) {
            return Asymmetric.encryptWithPublicKey(algorithm.toString(), publicKey, data);
        }

        public static CryptoObject encryptWithPrivateKey(CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.encryptWithPublicKey(algorithm.toString(), privateKey, data);
        }

        public static CryptoObject decryptWithPublicKey(CryptoKey publicKey, CryptoObject data) {
            return Asymmetric.decryptWithPublicKey(algorithm.toString(), publicKey, data);
        }

        public static CryptoObject decryptWithPrivateKey(CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.decryptWithPrivateKey(algorithm.toString(), privateKey, data);
        }

        public static CryptoObject sign(SM2SignAlgorithm algorithm, CryptoKey privateKey, CryptoObject data) {
            return Asymmetric.sign(algorithm.toString(), privateKey, data);
        }

        public static boolean verify(SM2SignAlgorithm algorithm, CryptoKey publicKey, CryptoObject data, CryptoObject sign) {
            return Asymmetric.verify(algorithm.toString(), publicKey, data, sign);
        }
    }

    public static class Asymmetric {

        public static CryptoObject encryptWithPublicKey(String algorithm, CryptoKey publicKey, CryptoObject data) {
            return CryptoObject.of(AsymmetricCrypto.encrypt(algorithm, publicKey.builder(algorithm).publicKey(), data.bytes()));
        }

        public static CryptoObject encryptWithPrivateKey(String algorithm, CryptoKey privateKey, CryptoObject data) {
            return CryptoObject.of(AsymmetricCrypto.encrypt(algorithm, privateKey.builder(algorithm).privateKey(), data.bytes()));
        }

        public static CryptoObject decryptWithPublicKey(String algorithm, CryptoKey publicKey, CryptoObject data) {
            return CryptoObject.of(AsymmetricCrypto.decrypt(algorithm, publicKey.builder(algorithm).publicKey(), data.bytes()));
        }

        public static CryptoObject decryptWithPrivateKey(String algorithm, CryptoKey privateKey, CryptoObject data) {
            return CryptoObject.of(AsymmetricCrypto.decrypt(algorithm, privateKey.builder(algorithm).privateKey(), data.bytes()));
        }

        public static CryptoObject sign(String algorithm, CryptoKey privateKey, CryptoObject data) {
            return CryptoObject.of(AsymmetricCrypto.sign(algorithm, privateKey.builder(algorithm).privateKey(), data.bytes()));
        }

        public static boolean verify(String algorithm, CryptoKey publicKey, CryptoObject data, CryptoObject sign) {
            return AsymmetricCrypto.verify(algorithm, publicKey.builder(algorithm).publicKey(), data.bytes(), sign.bytes());
        }
    }
}
