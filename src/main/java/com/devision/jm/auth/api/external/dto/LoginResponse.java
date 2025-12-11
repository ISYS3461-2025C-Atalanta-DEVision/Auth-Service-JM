package com.devision.jm.auth.api.external.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Login Response DTO (External)
 *
 * Response after successful authentication.
 * Contains access token (JWE encrypted - 2.2.1) and refresh token (2.3.3).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class LoginResponse {

    /**
     * JWT Access Token (JWE encrypted - 2.2.1 Ultimo)
     * Payload is encrypted and cannot be read by unauthorized parties.
     * Frontend should use expiresIn field to track expiration.
     */
    private String accessToken;

    /**
     * Refresh Token for token renewal (2.3.3)
     */
    private String refreshToken;

    /**
     * Token type (Bearer)
     */
    @Builder.Default
    private String tokenType = "Bearer";

    /**
     * Access token expiration time in seconds
     */
    private Long expiresIn;

    /**
     * Refresh token expiration time in seconds
     */
    private Long refreshExpiresIn;

    /**
     * User information
     */
    private UserInfo user;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class UserInfo {
        private String id;
        private String email;
        private String role;
        private String companyName;
        private String country;
    }
}
