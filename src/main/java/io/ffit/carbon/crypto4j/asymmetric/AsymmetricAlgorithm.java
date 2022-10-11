package io.ffit.carbon.crypto4j.asymmetric;

import io.ffit.carbon.crypto4j.Algorithm;

/**
 * Asymmetrical Algorithm
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum AsymmetricAlgorithm {
    RSA(Algorithm.RSA),
    SM2(Algorithm.SM2),
    ;
    private final Algorithm algorithm;
    AsymmetricAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    public String toString() {
        return algorithm.toString();
    }
}
