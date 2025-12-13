package com.devision.jm.auth.model.enums;

/**
 * Account Status Enumeration
 *
 * Represents the various states of a user account.
 */
public enum AccountStatus {
    PENDING_ACTIVATION,  // Account created but not yet activated via email (1.1.3)
    ACTIVE,              // Account is active and can login
    DEACTIVATED,         // Account deactivated by admin (6.1.2)
    LOCKED               // Account locked due to too many failed login attempts (2.2.2)
}
