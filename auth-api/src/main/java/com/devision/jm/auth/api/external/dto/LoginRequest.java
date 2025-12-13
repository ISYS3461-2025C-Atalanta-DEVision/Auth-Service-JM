package com.devision.jm.auth.api.external.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Request DTO (External)
 *
 * Used for authentication endpoint.
 * Implements requirement 2.1.1.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    private String password;

    /**
     * Optional: Device information for refresh token tracking
     */
    private String deviceInfo;
}
