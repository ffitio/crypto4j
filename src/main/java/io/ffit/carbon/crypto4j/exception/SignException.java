package io.ffit.carbon.crypto4j.exception;

/**
 * Encrypt Exception
 *
 * @author Lay
 * @date 2022/10/9
 */
public class SignException extends RuntimeException {
    private String algorithm;
    public SignException(String algorithm) {
        super(String.format("%s signed failed", algorithm));
    }

    public SignException(String algorithm, Throwable cause) {
        super(String.format("%s signed failed", algorithm), cause);
    }
}
