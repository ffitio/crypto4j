package io.ffit.carbon.crypto4j;

/**
 * Algorithm
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum Algorithm {
    /**
     * Digest Algorithm
     */
    SHA1("SHA1"),
    SHA2("SHA2"),
    SHA3("SHA3"),
    Keccak("Keccak"),
    Shake("Shake"),
    SM3("SM3"),
    MD2("MD2"),
    MD4("MD4"),
    MD5("MD5"),

    /**
     * Symmetric Algorithm
     */
    AES("AES"),
    DES("DES"),
    DESede("DESede"),
    SM4("SM4"),

    /**
     * Asymmetric Algorithm
     */
    RSA("RSA"),
    SM2("SM2"),
    ;
    private final String name;
    Algorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
