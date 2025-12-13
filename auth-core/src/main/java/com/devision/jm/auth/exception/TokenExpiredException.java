package com.devision.jm.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when token is expired (2.2.3)
 */
public class TokenExpiredException extends AuthException {

    public TokenExpiredException() {
        super("Token has expired", HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED");
    }

    public TokenExpiredException(String tokenType) {
        super(tokenType + " token has expired", HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED");
    }
}
