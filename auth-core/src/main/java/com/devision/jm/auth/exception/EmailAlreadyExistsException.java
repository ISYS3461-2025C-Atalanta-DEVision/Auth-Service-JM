package com.devision.jm.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when email already exists (1.1.2)
 */
public class EmailAlreadyExistsException extends AuthException {

    public EmailAlreadyExistsException(String email) {
        super("Email already registered: " + email, HttpStatus.CONFLICT, "EMAIL_EXISTS");
    }
}
