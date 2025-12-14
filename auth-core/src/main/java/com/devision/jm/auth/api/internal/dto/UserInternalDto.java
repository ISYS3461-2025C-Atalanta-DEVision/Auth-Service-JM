package com.devision.jm.auth.api.internal.dto;

import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * User Internal DTO
 *
 * Internal representation of user data for service layer operations.
 * Contains authentication fields only (for internal processing).
 *
 * Microservice Architecture (A.3.1):
 * - Auth Service owns: email, password, tokens, security fields
 * - Profile Service owns: company info, contact info (via Kafka)
 *
 * Implements A.2.6: Internal DTOs are only accessible by classes within the module.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserInternalDto {

    private String id;
    private String email;
    private String passwordHash;
    private Role role;
    private AccountStatus status;
    private AuthProvider authProvider;
    private String providerId;

    // Security fields (2.2.2)
    private Integer failedLoginAttempts;
    private LocalDateTime lastFailedLogin;
    private LocalDateTime lockedUntil;

    // Activation tokens (1.1.3)
    private String activationToken;
    private LocalDateTime activationTokenExpiry;

    // Audit
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime lastLogin;
    private LocalDateTime lastPasswordChange;
}
