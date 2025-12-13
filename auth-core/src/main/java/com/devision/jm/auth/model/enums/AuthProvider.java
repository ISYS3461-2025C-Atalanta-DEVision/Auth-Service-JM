package com.devision.jm.auth.model.enums;

/**
 * Authentication Provider Enumeration
 *
 * Defines the authentication methods available.
 * Supports SSO (Ultimo 1.3.1, 1.3.2)
 */
public enum AuthProvider {
    LOCAL,      // Traditional email/password authentication
    GOOGLE,     // Google SSO
    MICROSOFT,  // Microsoft SSO
    FACEBOOK,   // Facebook SSO
    GITHUB      // GitHub SSO
}
