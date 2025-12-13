package com.devision.jm.auth.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Base Authentication Exception
 */
@Getter
public class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final String errorCode;

    public AuthException(String message, HttpStatus status, String errorCode) {
        super(message);
        this.status = status;
        this.errorCode = errorCode;
    }

    public AuthException(String message, HttpStatus status) {
        this(message, status, null);
    }
}
