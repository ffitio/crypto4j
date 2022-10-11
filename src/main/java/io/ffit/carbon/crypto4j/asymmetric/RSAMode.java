package io.ffit.carbon.crypto4j.asymmetric;

/**
 * Symmetric Encrypt Mode
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum RSAMode {
    ECB("ECB"),
    None("None"),
    ;

    private String name;
    RSAMode(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
