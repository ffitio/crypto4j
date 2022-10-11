package io.ffit.carbon.crypto4j.asymmetric;

/**
 * Signature Algorithm
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum RSASignAlgorithm {
    SHA1WithRSA("SHA1WithRSA"),
    SHA224WithRSA("SHA224WithRSA"),
    SHA256WithRSA("SHA256WithRSA"),
    SHA384WithRSA("SHA384WithRSA"),
    SHA512WithRSA("SHA512WithRSA"),
    ;

    private final String name;
    RSASignAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
