package io.ffit.carbon.crypto4j.exception;

/**
 * Encrypt Exception
 *
 * @author Lay
 * @date 2022/10/9
 */
public class DecryptException extends RuntimeException {
    private String algorithm;
    public DecryptException(String algorithm) {
        super(String.format("%s decrypt failed", algorithm));
    }

    public DecryptException(String algorithm, Throwable cause) {
        super(String.format("%s decrypt failed", algorithm), cause);
    }
}
