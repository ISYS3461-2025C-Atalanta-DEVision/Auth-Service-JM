package com.devision.jm.auth.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception thrown when account is locked due to brute-force protection (2.2.2)
 */
public class AccountLockedException extends AuthException {

    public AccountLockedException(long secondsRemaining) {
        super("Account is locked. Please try again in " + secondsRemaining + " seconds",
                HttpStatus.LOCKED, "ACCOUNT_LOCKED");
    }

    public AccountLockedException() {
        super("Account is locked due to too many failed login attempts",
                HttpStatus.LOCKED, "ACCOUNT_LOCKED");
    }
}
