package io.ffit.carbon.crypto4j.symmetric;

/**
 * Symmetric Encrypt Mode
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum SymmetricMode {
    ECB("ECB"),
    CBC("CBC"),
    OFB("OFB"),
    CFB("CFB"),
    ;

    private String name;
    SymmetricMode(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
