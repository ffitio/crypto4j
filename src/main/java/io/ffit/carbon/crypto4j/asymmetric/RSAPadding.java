package io.ffit.carbon.crypto4j.asymmetric;

/**
 * Padding Type
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum RSAPadding {
    NoPadding("NoPadding"),
    PKCS1Padding("PKCS1Padding"),
    ISO9796_1Padding("ISO9796-1Padding"),
    OAEPPadding("OAEPPadding"),
    OAEPWithMD5AndMGF1Padding("OAEPWithMD5AndMGF1Padding"),
    OAEPWithSHA1AndMGF1Padding("OAEPWithSHA1AndMGF1Padding"),
    OAEPWithSHA224AndMGF1Padding("OAEPWithSHA224AndMGF1Padding"),
    OAEPWithSHA256AndMGF1Padding("OAEPWithSHA256AndMGF1Padding"),
    OAEPWithSHA384AndMGF1Padding("OAEPWithSHA384AndMGF1Padding"),
    OAEPWithSHA512AndMGF1Padding("OAEPWithSHA512AndMGF1Padding"),
    OAEPWithSHA3_224AndMGF1Padding("OAEPWithSHA3-224AndMGF1Padding"),
    OAEPWithSHA3_256AndMGF1Padding("OAEPWithSHA3-256AndMGF1Padding"),
    OAEPWithSHA3_384AndMGF1Padding("OAEPWithSHA3-384AndMGF1Padding"),
    OAEPWithSHA3_512AndMGF1Padding("OAEPWithSHA3-512AndMGF1Padding"),
    ;
    private final String name;
    RSAPadding(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
