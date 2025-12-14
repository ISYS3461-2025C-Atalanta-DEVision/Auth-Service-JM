package com.devision.jm.auth.api.external.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Registration Response DTO (External)
 *
 * Response after successful company registration.
 * Profile data is managed by Profile Service (Microservice Architecture A.3.1).
 *
 * Auth Service only returns:
 * - userId for reference
 * - email for confirmation
 * - message about activation email
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegistrationResponse {

    /**
     * User ID created in Auth Service
     * This ID is used as reference in Profile Service
     */
    private String userId;

    /**
     * Email address (for confirmation)
     */
    private String email;

    /**
     * Human-readable message
     */
    private String message;
}
