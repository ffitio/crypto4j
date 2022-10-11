package io.ffit.carbon.crypto4j.asymmetric;

/**
 * Signature Algorithm
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum SM2SignAlgorithm {
    SM3WithSM2("SM3WithSM2"),
    ;

    private final String name;
    SM2SignAlgorithm(String name) {
        this.name = name;
    }

    @Override
    public String toString() {
        return name;
    }
}
