package com.devision.jm.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when account is not yet activated (1.1.3)
 */
public class AccountNotActivatedException extends AuthException {

    public AccountNotActivatedException() {
        super("Account is not activated. Please check your email for activation link",
                HttpStatus.FORBIDDEN, "ACCOUNT_NOT_ACTIVATED");
    }
}
