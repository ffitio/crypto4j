package io.ffit.carbon.crypto4j.exception;

/**
 * Encrypt Exception
 *
 * @author Lay
 * @date 2022/10/9
 */
public class EncryptException extends RuntimeException {
    private String algorithm;
    public EncryptException(String algorithm) {
        super(String.format("%s encrypt failed", algorithm));
    }

    public EncryptException(String algorithm, Throwable cause) {
        super(String.format("%s encrypt failed", algorithm), cause);
    }
}
