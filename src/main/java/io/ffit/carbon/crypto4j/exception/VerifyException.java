package io.ffit.carbon.crypto4j.exception;

/**
 * Encrypt Exception
 *
 * @author Lay
 * @date 2022/10/9
 */
public class VerifyException extends RuntimeException {
    private String algorithm;
    public VerifyException(String algorithm) {
        super(String.format("%s sign verify failed", algorithm));
    }

    public VerifyException(String algorithm, Throwable cause) {
        super(String.format("%s sign verify failed", algorithm), cause);
    }
}
