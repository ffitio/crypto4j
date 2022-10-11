package io.ffit.carbon.crypto4j.digest;

/**
 * Digest Algorithm
 *
 * @author Lay
 * @date 2022/10/8
 */
public enum HMacAlgorithm {
    /**
     * SHA-1
     */
    SHA1("HMacSHA1"),

    /**
     * SHA-224
     */
    SHA_224("HMacSHA224"),

    /**
     * SHA-256
     */
    SHA_256("HMacSHA256"),

    /**
     * SHA-384
     */
    SHA_384("HMacSHA384"),

    /**
     * SHA-512
     */
    SHA_512("HMacSHA512"),

    /**
     * SHA-512/224
     */
    SHA_512_224("HMacSHA512/224"),

    /**
     * SHA-512/256
     */
    SHA_512_256("HMacSHA512/256"),

    /**
     * SHA3-224
     */
    SHA3_224("HMacSHA3-224"),

    /**
     * SHA3-256
     */
    SHA3_256("HMacSHA3-256"),

    /**
     * SHA3-384
     */
    SHA3_384("HMacSHA3-384"),

    /**
     * SHA3-512
     */
    SHA3_512("HMacSHA3-512"),

    /**
     * Keccak-224
     */
    Keccak_224("HMacKeccak224"),

    /**
     * Keccak-256
     */
    Keccak_256("HMacKeccak256"),

    /**
     * Keccak-384
     */
    Keccak_384("HMacKeccak384"),

    /**
     * Keccak-224
     */
    Keccak_512("HMacKeccak512"),

    /**
     * MD2
     */
    MD2("HMacMD2"),

    /**
     * MD4
     */
    MD4("HMacMD4"),

    /**
     * MD5
     */
    MD5("HMacMD5"),

    /**
     * SM3
     */
    SM3("HMacSM3"),
    ;

    private final String name;

    HMacAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
