package com.devision.jm.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when token is invalid or revoked
 */
public class InvalidTokenException extends AuthException {

    public InvalidTokenException() {
        super("Invalid or revoked token", HttpStatus.UNAUTHORIZED, "INVALID_TOKEN");
    }

    public InvalidTokenException(String message) {
        super(message, HttpStatus.UNAUTHORIZED, "INVALID_TOKEN");
    }
}
