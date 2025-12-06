package com.devision.jm.auth.model.entity;

import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.time.LocalDateTime;

/**
 * User Entity
 *
 * Represents both Company and Admin users in the authentication system.
 *
 * Implements requirements:
 * - 1.1.1: Registration with Email, Password, Country (mandatory), Phone, Street, City (optional)
 * - 1.1.2: Unique email constraint
 * - 1.3.1, 1.3.2: SSO support via authProvider field
 */
@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email", unique = true),
        @Index(name = "idx_user_country", columnList = "country"),
        @Index(name = "idx_user_status", columnList = "status")
})
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class User extends BaseEntity {

    // ==================== Authentication Fields ====================

    @Column(name = "email", nullable = false, unique = true, length = 255)
    private String email;

    @Column(name = "password_hash", length = 255)
    private String passwordHash;  // Null for SSO users (1.3.2)

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private AccountStatus status;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_provider", nullable = false)
    private AuthProvider authProvider;

    @Column(name = "provider_id")
    private String providerId;  // External provider user ID for SSO

    // ==================== Contact Information ====================

    @Column(name = "phone_number", length = 20)
    private String phoneNumber;  // Optional (1.1.1)

    @Column(name = "street_address", length = 255)
    private String streetAddress;  // Optional (1.1.1)

    @Column(name = "city", length = 100)
    private String city;  // Optional (1.1.1)

    @Column(name = "country", nullable = false, length = 100)
    private String country;  // Mandatory (1.1.1, 1.24 - dropdown selection)

    // ==================== Company Information ====================

    @Column(name = "company_name", length = 255)
    private String companyName;

    // ==================== Account Security ====================

    @Builder.Default
    @Column(name = "failed_login_attempts")
    private Integer failedLoginAttempts = 0;  // For brute-force protection (2.2.2)

    @Column(name = "last_failed_login")
    private LocalDateTime lastFailedLogin;

    @Column(name = "locked_until")
    private LocalDateTime lockedUntil;  // Account lock expiration

    // ==================== Activation ====================

    @Column(name = "activation_token")
    private String activationToken;  // For email activation (1.1.3)

    @Column(name = "activation_token_expiry")
    private LocalDateTime activationTokenExpiry;

    // ==================== Password Reset ====================

    @Column(name = "password_reset_token")
    private String passwordResetToken;

    @Column(name = "password_reset_token_expiry")
    private LocalDateTime passwordResetTokenExpiry;

    @Column(name = "last_password_change")
    private LocalDateTime lastPasswordChange;

    // ==================== Audit Fields ====================

    @Column(name = "last_login")
    private LocalDateTime lastLogin;

    // ==================== Helper Methods ====================

    /**
     * Check if account is locked due to brute-force protection
     */
    public boolean isAccountLocked() {
        if (lockedUntil == null) {
            return false;
        }
        return LocalDateTime.now().isBefore(lockedUntil);
    }

    /**
     * Check if account can attempt login
     */
    public boolean canAttemptLogin() {
        return status == AccountStatus.ACTIVE && !isAccountLocked();
    }

    /**
     * Check if user uses SSO authentication
     */
    public boolean isSsoUser() {
        return authProvider != AuthProvider.LOCAL;
    }

    /**
     * Increment failed login attempts (for 2.2.2)
     */
    public void incrementFailedLoginAttempts() {
        this.failedLoginAttempts = (this.failedLoginAttempts == null ? 0 : this.failedLoginAttempts) + 1;
        this.lastFailedLogin = LocalDateTime.now();
    }

    /**
     * Reset failed login attempts after successful login
     */
    public void resetFailedLoginAttempts() {
        this.failedLoginAttempts = 0;
        this.lastFailedLogin = null;
        this.lockedUntil = null;
    }
}
