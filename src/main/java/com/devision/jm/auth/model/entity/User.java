package com.devision.jm.auth.model.entity;

import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.springframework.data.mongodb.core.index.CompoundIndex;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDateTime;

/**
 * User Document (MongoDB)
 *
 * Represents both Company and Admin users in the authentication system.
 *
 * Implements requirements:
 * - 1.1.1: Registration with Email, Password, Country (mandatory), Phone, Street, City (optional)
 * - 1.1.2: Unique email constraint
 * - 1.3.1, 1.3.2: SSO support via authProvider field
 */
@Document(collection = "users")
@CompoundIndex(name = "idx_country_status", def = "{'country': 1, 'status': 1}")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class User extends BaseEntity {

    // ==================== Authentication Fields ====================

    @Indexed(unique = true)
    @Field("email")
    private String email;

    @Field("password_hash")
    private String passwordHash;  // Null for SSO users (1.3.2)

    @Field("role")
    private Role role;

    @Indexed
    @Field("status")
    private AccountStatus status;

    @Field("auth_provider")
    private AuthProvider authProvider;

    @Field("provider_id")
    private String providerId;  // External provider user ID for SSO

    // ==================== Contact Information ====================

    @Field("phone_number")
    private String phoneNumber;  // Optional (1.1.1)

    @Field("street_address")
    private String streetAddress;  // Optional (1.1.1)

    @Field("city")
    private String city;  // Optional (1.1.1)

    @Indexed
    @Field("country")
    private String country;  // Mandatory (1.1.1, 1.24 - dropdown selection)

    // ==================== Company Information ====================

    @Field("company_name")
    private String companyName;

    // ==================== Account Security ====================

    @Builder.Default
    @Field("failed_login_attempts")
    private Integer failedLoginAttempts = 0;  // For brute-force protection (2.2.2)

    @Field("last_failed_login")
    private LocalDateTime lastFailedLogin;

    @Field("locked_until")
    private LocalDateTime lockedUntil;  // Account lock expiration

    // ==================== Activation ====================

    @Indexed(sparse = true)
    @Field("activation_token")
    private String activationToken;  // For email activation (1.1.3)

    @Field("activation_token_expiry")
    private LocalDateTime activationTokenExpiry;

    // ==================== Password Reset ====================

    @Indexed(sparse = true)
    @Field("password_reset_token")
    private String passwordResetToken;

    @Field("password_reset_token_expiry")
    private LocalDateTime passwordResetTokenExpiry;

    @Field("last_password_change")
    private LocalDateTime lastPasswordChange;

    // ==================== Audit Fields ====================

    @Field("last_login")
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
