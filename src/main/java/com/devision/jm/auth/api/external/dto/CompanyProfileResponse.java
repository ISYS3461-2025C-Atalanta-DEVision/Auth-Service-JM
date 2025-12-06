package com.devision.jm.auth.api.external.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Company Profile Response DTO (External)
 *
 * Response for company profile data.
 * Implements A.2.5: Only presents necessary data (excludes sensitive info like password hash, credit card).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CompanyProfileResponse {

    private String id;
    private String email;
    private String companyName;
    private String country;
    private String city;
    private String streetAddress;
    private String phoneNumber;
    private String status;
    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    // Note: Sensitive fields NOT included per A.2.5:
    // - passwordHash
    // - activationToken
    // - passwordResetToken
    // - failedLoginAttempts
    // - lockedUntil
}
