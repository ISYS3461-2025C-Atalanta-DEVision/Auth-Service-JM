package com.devision.jm.auth.api.internal.dto;

import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * User Internal DTO
 *
 * Internal representation of user data for service layer operations.
 * Contains all user fields including sensitive ones (for internal processing only).
 *
 * Implements A.2.6: Internal DTOs are only accessible by classes within the module.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInternalDto {

    private UUID id;
    private String email;
    private String passwordHash;
    private Role role;
    private AccountStatus status;
    private AuthProvider authProvider;
    private String providerId;

    // Contact info
    private String phoneNumber;
    private String streetAddress;
    private String city;
    private String country;

    // Company info
    private String companyName;

    // Security fields
    private Integer failedLoginAttempts;
    private LocalDateTime lastFailedLogin;
    private LocalDateTime lockedUntil;

    // Tokens
    private String activationToken;
    private LocalDateTime activationTokenExpiry;
    private String passwordResetToken;
    private LocalDateTime passwordResetTokenExpiry;

    // Audit
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLogin;
    private LocalDateTime lastPasswordChange;
}
