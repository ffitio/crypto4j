package io.ffit.carbon.crypto4j.digest;

/**
 * Digest Algorithm
 *
 * @author Lay
 * @date 2022/10/8
 */
public enum DigestAlgorithm {
    /**
     * SHA-1
     */
    SHA1("SHA1"),

    /**
     * SHA-224
     */
    SHA_224("SHA224"),

    /**
     * SHA-256
     */
    SHA_256("SHA256"),

    /**
     * SHA-384
     */
    SHA_384("SHA384"),

    /**
     * SHA-512
     */
    SHA_512("SHA512"),

    /**
     * SHA-512/224
     */
    SHA_512_224("SHA512/224"),

    /**
     * SHA-512/256
     */
    SHA_512_256("SHA512/256"),

    /**
     * SHA3-224
     */
    SHA3_224("SHA3-224"),

    /**
     * SHA3-256
     */
    SHA3_256("SHA3-256"),

    /**
     * SHA3-384
     */
    SHA3_384("SHA3-384"),

    /**
     * SHA3-512
     */
    SHA3_512("SHA3-512"),

    /**
     * Keccak-224
     */
    Keccak_224("Keccak-224"),

    /**
     * Keccak-256
     */
    Keccak_256("Keccak-256"),

    /**
     * Keccak-384
     */
    Keccak_384("Keccak-384"),

    /**
     * Keccak-224
     */
    Keccak_512("Keccak-512"),

    /**
     * MD2
     */
    MD2("MD2"),

    /**
     * MD4
     */
    MD4("MD4"),

    /**
     * MD5
     */
    MD5("MD5"),

    /**
     * SM3
     */
    SM3("SM3"),
    ;

    private final String name;

    DigestAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
