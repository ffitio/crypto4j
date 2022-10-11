package io.ffit.carbon.crypto4j.entity;

import io.ffit.carbon.crypto4j.CryptoFactory;
import io.ffit.carbon.crypto4j.asymmetric.AsymmetricAlgorithm;

import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Crypto Key
 *
 * @author Lay
 * @date 2022/10/11
 */
public class CryptoKey {

    private final CryptoObject source;

    private CryptoKey(CryptoObject source) {
        this.source = source;
    }

    public static CryptoKey of(byte[] source) {
        return new CryptoKey(CryptoObject.of(source));
    }

    public static CryptoKey fromBase64(String base64) {
        return new CryptoKey(CryptoObject.fromBase64(base64));
    }

    public static CryptoKey fromHex(String hex) {
        return new CryptoKey(CryptoObject.fromHex(hex));
    }

    public KeyBuilder builder(String algorithm) {
        return new KeyBuilder(algorithm, source);
    }

    public Key build(String algorithm, boolean isPrivate) {
        KeyBuilder builder = new KeyBuilder(algorithm, source);
        if (isPrivate) {
            return builder.privateKey();
        }
        return builder.publicKey();
    }

    public static class KeyBuilder {
        private final String algorithm;
        protected final CryptoObject source;
        private KeyBuilder(String algorithm, CryptoObject source) {
            if (AsymmetricAlgorithm.SM2.toString().toUpperCase().equals(algorithm.toUpperCase())) {
                this.algorithm = "EC";
            } else {
                this.algorithm = algorithm;
            }
            this.source = source;
        }

        public PublicKey publicKey() {
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(source.bytes());
            KeyFactory kf = CryptoFactory.keyFactoryOf(algorithm);
            try {
                return kf.generatePublic(keySpec);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        public PrivateKey privateKey() {
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(source.bytes());
            KeyFactory kf = CryptoFactory.keyFactoryOf(algorithm);
            try {
                return kf.generatePrivate(keySpec);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
