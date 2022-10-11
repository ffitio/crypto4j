package io.ffit.carbon.crypto4j.symmetric;

/**
 * Padding Type
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum SymmetricPadding {
    PKCS5Padding("PKCS5Padding"),
    PKCS7Padding("PKCS7Padding"),
    ISO10126Padding("ISO10126Padding"),
    ZeroPadding("ZeroBytePadding"),
    NoPadding("NoPadding"),
    ;
    private final String name;
    SymmetricPadding(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
