package io.ffit.carbon.crypto4j.symmetric;

import io.ffit.carbon.crypto4j.Algorithm;

/**
 * Symmetric Algorithm
 *
 * @author Lay
 * @date 2022/10/9
 */
public enum SymmetricAlgorithm {
    AES(Algorithm.AES),
    DES(Algorithm.DES),
    DESede(Algorithm.DESede),
    SM4(Algorithm.SM4)
    ;

    private final Algorithm algorithm;

    SymmetricAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
    }

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    @Override
    public String toString() {
        return algorithm.toString();
    }
}
