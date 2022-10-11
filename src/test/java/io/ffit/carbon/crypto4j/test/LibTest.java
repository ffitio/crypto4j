package io.ffit.carbon.crypto4j.test;

import io.ffit.carbon.crypto4j.asymmetric.AsymmetricAlgorithm;
import io.ffit.carbon.crypto4j.asymmetric.AsymmetricCrypto;
import io.ffit.carbon.crypto4j.digest.DigestAlgorithm;
import io.ffit.carbon.crypto4j.digest.DigestCrypto;
import io.ffit.carbon.crypto4j.digest.HMacAlgorithm;
import io.ffit.carbon.crypto4j.entity.CryptoKey;
import io.ffit.carbon.crypto4j.entity.CryptoObject;
import io.ffit.carbon.crypto4j.symmetric.SymmetricAlgorithm;
import io.ffit.carbon.crypto4j.symmetric.SymmetricCrypto;
import io.ffit.carbon.crypto4j.symmetric.SymmetricMode;
import io.ffit.carbon.crypto4j.symmetric.SymmetricPadding;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

/**
 * Tester
 *
 * @author Lay
 * @date 2022/10/11
 */
public class LibTest {

    public static final Map<DigestAlgorithm, String> DIGEST_RESULT;
    public static final Map<HMacAlgorithm, String> HMAC_DIGEST_RESULT;
    public static final String DATA = "hello world";
    public static final String KEY = "crypto4j";
    public static final String SYM_KEY = "0000000000000000";
    public static final String PUBLIC_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPKSLcwuKgAknrfhEasKD+LtpS0mceyAsPAeglJI/NHIRCoA37oREyTq/RntH4+Zgy+djlN4Jx8OLAxhgYYDJeM9k/9lsXPQkop9HJHe6vGQJDhJUrCdihoravA8z3rglkT1zbcs1TjPZ3AlbTTfkclldNSyU6Jh5/k6+ezVOv7wIDAQAB";
    public static final String PRIVATE_KEY = "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBAI8pItzC4qACSet+ERqwoP4u2lLSZx7ICw8B6CUkj80chEKgDfuhETJOr9Ge0fj5mDL52OU3gnHw4sDGGBhgMl4z2T/2Wxc9CSin0ckd7q8ZAkOElSsJ2KGitq8DzPeuCWRPXNtyzVOM9ncCVtNN+RyWV01LJTomHn+Tr57NU6/vAgMBAAECgYA6YzOlyBI34lcVpbgCI7G1mZRPnSKTqlDgUQ3GQFAp/oxuw+qQCxQBaZhJrTXEDsAlYkM00VvxbqZ8qw5eurUvnFWSGhyEk8Jj6K/Jb5/3M6khvwEPFnoN5aia3W5wZxlchaN8KDpId48/AcqcJc9Qu4FUOG918n+q6bjUNR3mqQJBAMK+qYDeEtz5hsaqjNlH9ugjNCLnDwv6rpaMpGGv5y9BPC7povTsdxdUOyk5arundnA9xOrXhqBK2ilAdaQaGFUCQQC8MMtF30H05cCruQFo6IKAnIBZI4U5r/kpKRG19JdN949asQRzIMj66ySJLJlidvo0I9JbHZHxrKHx5wZ4sHszAkBoKSxmNeFm+buhlOUi7j/cp7+iD23X3Wv2MCFX8oq3lq/G88XqNHP6MV43TXOODSLnI9KoPUDPiVmoiMajUCXFAkB5ozBAIWYIXNiEJjh7Do4LgxySgRsDhnKN4DXKXiXOB01pWTF/GJnPVV1wLJuXwT9HpD+7FQnYI7UpHiJYr/lxAkAs5oLbauW/RfT9docrwtgKldgMNyQxpyNOKKAFxuLtd/9gY/TQNCfpk2P01AWI7qALCyvpfn1qPCvtkwJO7Lm0";
    public static final String SM2_PUBLIC_KEY = "MIIBMzCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBA0IABNhAQYMoAnb/5hXrcLGFFJM90Yo/kAaTqT6OBTJYkQQQqDivuI0c1CrfIRQL5gqtzhFP6srIJWs8rnFLKtP+f2Q=";
    public static final String SM2_PRIVATE_KEY = "MIICSwIBADCB7AYHKoZIzj0CATCB4AIBATAsBgcqhkjOPQEBAiEA/////v////////////////////8AAAAA//////////8wRAQg/////v////////////////////8AAAAA//////////wEICjp+p6dn140TVqeS89lCafzl4n1FauPkt28vUFNlA6TBEEEMsSuLB8ZgRlfmQRGajnJlI/jC7/yZgvhcVpFiTNMdMe8Nzai9PZ3nFm9zuNraSFT0KmHfMYqR0AC3zLlITnwoAIhAP////7///////////////9yA99rIcYFK1O79Ak51UEjAgEBBIIBVTCCAVECAQEEIPKpL8BxOaHBaaQuH+9DzBHIAsGbOZN5w716Fwj52SUmoIHjMIHgAgEBMCwGByqGSM49AQECIQD////+/////////////////////wAAAAD//////////zBEBCD////+/////////////////////wAAAAD//////////AQgKOn6np2fXjRNWp5Lz2UJp/OXifUVq4+S3by9QU2UDpMEQQQyxK4sHxmBGV+ZBEZqOcmUj+MLv/JmC+FxWkWJM0x0x7w3NqL09necWb3O42tpIVPQqYd8xipHQALfMuUhOfCgAiEA/////v///////////////3ID32shxgUrU7v0CTnVQSMCAQGhRANCAATYQEGDKAJ2/+YV63CxhRSTPdGKP5AGk6k+jgUyWJEEEKg4r7iNHNQq3yEUC+YKrc4RT+rKyCVrPK5xSyrT/n9k";

    static {
        DIGEST_RESULT = new HashMap<>();
        DIGEST_RESULT.put(DigestAlgorithm.MD2, "d9cce882ee690a5c1ce70beff3a78c77");
        DIGEST_RESULT.put(DigestAlgorithm.MD4, "aa010fbc1d14c795d86ef98c95479d17");
        DIGEST_RESULT.put(DigestAlgorithm.MD5, "5eb63bbbe01eeed093cb22bb8f5acdc3");
        DIGEST_RESULT.put(DigestAlgorithm.SHA1, "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_224, "2f05477fc24bb4faefd86517156dafdecec45b8ad3cf2522a563582b");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_384, "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_512, "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_512_224, "22e0d52336f64a998085078b05a6e37b26f8120f43bf4db4c43a64ee");
        DIGEST_RESULT.put(DigestAlgorithm.SHA_512_256, "0ac561fac838104e3f2e4ad107b4bee3e938bf15f2b15f009ccccd61a913f017");
        DIGEST_RESULT.put(DigestAlgorithm.SHA3_224, "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5");
        DIGEST_RESULT.put(DigestAlgorithm.SHA3_256, "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938");
        DIGEST_RESULT.put(DigestAlgorithm.SHA3_384, "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b");
        DIGEST_RESULT.put(DigestAlgorithm.SHA3_512, "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
        DIGEST_RESULT.put(DigestAlgorithm.Keccak_224, "25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568");
        DIGEST_RESULT.put(DigestAlgorithm.Keccak_256, "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad");
        DIGEST_RESULT.put(DigestAlgorithm.Keccak_384, "65fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f");
        DIGEST_RESULT.put(DigestAlgorithm.Keccak_512, "3ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d");
        DIGEST_RESULT.put(DigestAlgorithm.SM3, "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88");

        HMAC_DIGEST_RESULT = new HashMap<>();
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.MD2, "985a281f60d999bb62b8e3d5ccff0f73");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.MD4, "a2c136eb2bfc13cd7e7bc3f310681477");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.MD5, "6f5175f8fc1551133e7681089bb0564e");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA1, "f4ac2a9eee3500dd02b375d1075bf0c2fcce757b");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_224, "1fd2a9f082075b49e48c66cd5994606b197d20b5c23f19464ea13e9b");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_256, "98e8cf6a0b33205ee36861c6fb5fa128fe539317538a0922efc4677cde3b152f");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_384, "8ad3e0e64609b1a4fcb412bb304a7455642af7f92356df00bc61e2b697d89e5a0699fba10ad3b08f41f0d088cf2151ce");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_512, "2944ad7f84b401ef723af3f49b2fa48b66369d246c87ae9c1d75f9e4ebf9de01c0dce40fe42ef031bde447727f3b21fbb05e94e2d4dab957f1b20d03c609475f");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_512_224, "83901606dcccb4ece2631126c2debb67dcb2d94d126c5c747d0a4f57");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA_512_256, "58db3068ef0157f211aca41ca7d7bbd707ab302a04fe4cecd04a9b2650c8a1f5");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA3_224, "ea470c0dd90e3826ce553d677d178658bc2a266b45c331f45e55138d");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA3_256, "ad14dffec0a30c3a76970f94e0880b2b0f5cbbbe186fa9df5c958220f4430311");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA3_384, "e107692d676c034895e5bc8b425741bdbd4438c346ad34b69b2ebcf54a2a7a22ea928a9caf9ca23ab5ddec984d15706e");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SHA3_512, "3ab49e42969307a30ed46c3d9a5611b80eb1e1ad898a86120c7b55be92429c208591f9bf835b4f4c0704d913b7d4ed977398637d91a350cf56f8eb8761004760");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.Keccak_224, "95337e3428501151250bbd3a263918fb3084cfda9d9a3315dcc93ddd");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.Keccak_256, "6d715dc5afbb08bac591eb6c870031084c3cee255c39c20cac2adfb5c411849e");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.Keccak_384, "41ca6c129b3069dcfb8a078838f1877f0d3dfff528b21e5bfbe0f59d7816692090c0c444038ead00358d5afdc089c086");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.Keccak_512, "4262e3d1a174352fcb0a9555a82083fe584f11fa17c913d91b07dec2b3ea315976cf87519ee91847bccfdd31c93d980a785e41d2a7a305c97953c151995c8f9b");
        HMAC_DIGEST_RESULT.put(HMacAlgorithm.SM3, "7ff41f28f7f9f63b1526a3bc754b4e6b8c047abcf580b5ad87abbee9d3e9ce2e");
    }

    @Test
    public void testDigest() {
        System.out.printf("Digest Test of Data: %s\n", DATA);
        String encrypted;
        for (DigestAlgorithm algorithm : DigestAlgorithm.values()) {
            encrypted = CryptoObject.of(DigestCrypto.digest(algorithm.toString(), DATA.getBytes(StandardCharsets.UTF_8))).hex();
            System.out.printf("[%s] Result: %s\n", algorithm, encrypted);
            Assertions.assertEquals(DIGEST_RESULT.get(algorithm), encrypted);
        }

        System.out.printf("\nHMAC Digest Test of Data: %s Key: %s\n", DATA, KEY);
        for (HMacAlgorithm algorithm : HMacAlgorithm.values()) {
            encrypted = CryptoObject.of(DigestCrypto.hmac(algorithm.toString(), KEY.getBytes(StandardCharsets.UTF_8), DATA.getBytes(StandardCharsets.UTF_8))).hex();
            System.out.printf("[%s] Result: %s\n", algorithm.name(), encrypted);
            if (!HMAC_DIGEST_RESULT.get(algorithm).equals("")) {
                Assertions.assertEquals(HMAC_DIGEST_RESULT.get(algorithm), encrypted);
            }
        }
    }

    @Test
    public void testSymmetric() {
        byte[] encrypted = SymmetricCrypto.encrypt(SymmetricAlgorithm.AES, SymmetricMode.CBC, SymmetricPadding.PKCS7Padding,
                SYM_KEY.getBytes(StandardCharsets.UTF_8),
                SYM_KEY.getBytes(StandardCharsets.UTF_8),
                DATA.getBytes(StandardCharsets.UTF_8));
        String decrypted = CryptoObject.of(SymmetricCrypto.decrypt(SymmetricAlgorithm.AES, SymmetricMode.CBC, SymmetricPadding.PKCS7Padding,
                SYM_KEY.getBytes(StandardCharsets.UTF_8),
                SYM_KEY.getBytes(StandardCharsets.UTF_8),
                encrypted)).toString();
        Assertions.assertEquals(DATA, decrypted);
    }

    @Test
    public void testAsymmetric() {
        byte[] encrypted = AsymmetricCrypto.encrypt(AsymmetricAlgorithm.RSA.toString(), CryptoKey.fromBase64(PUBLIC_KEY).builder(AsymmetricAlgorithm.RSA.toString()).publicKey(), DATA.getBytes(StandardCharsets.UTF_8));
        byte[] decrypted = AsymmetricCrypto.decrypt(AsymmetricAlgorithm.RSA.toString(), CryptoKey.fromBase64(PRIVATE_KEY).builder(AsymmetricAlgorithm.RSA.toString()).privateKey(), encrypted);
        Assertions.assertEquals(DATA, CryptoObject.of(decrypted).toString());

        encrypted = AsymmetricCrypto.encrypt(AsymmetricAlgorithm.SM2.toString(), CryptoKey.fromBase64(SM2_PUBLIC_KEY).builder(AsymmetricAlgorithm.SM2.toString()).publicKey(), DATA.getBytes(StandardCharsets.UTF_8));
        decrypted = AsymmetricCrypto.decrypt(AsymmetricAlgorithm.SM2.toString(), CryptoKey.fromBase64(SM2_PRIVATE_KEY).builder(AsymmetricAlgorithm.SM2.toString()).privateKey(), encrypted);
        Assertions.assertEquals(DATA, CryptoObject.of(decrypted).toString());
    }
}
