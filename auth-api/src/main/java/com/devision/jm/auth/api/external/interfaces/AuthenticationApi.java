package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.*;

/**
 * Authentication API Interface (External)
 *
 * Defines external API contract for authentication operations.
 * These APIs are accessible by other modules (A.2.3, A.2.4).
 *
 * Microservice Architecture (A.3.1):
 * - Auth Service handles: registration, login, logout, tokens
 * - Profile Service handles: user profile (via Kafka)
 */
public interface AuthenticationApi {

    /**
     * Register new company account
     *
     * Flow:
     * 1. Auth Service creates user (email, password)
     * 2. Auth Service publishes UserCreatedEvent to Kafka
     * 3. Profile Service creates profile from event
     *
     * @param request Registration data
     * @return Registration response with userId
     */
    RegistrationResponse registerCompany(CompanyRegistrationRequest request);

    /**
     * Login with email/password
     */
    LoginResponse login(LoginRequest request, String ipAddress);

    /**
     * Refresh access token using refresh token
     */
    LoginResponse refreshToken(RefreshTokenRequest request);

    /**
     * Logout and revoke tokens
     */
    void logout(String accessToken, String refreshToken);

    /**
     * Activate account via email link
     */
    void activateAccount(String token);

    /**
     * Validate access token (used by API Gateway)
     */
    boolean validateToken(String token);

    // NOTE: getUserProfile is now handled by Profile Service
}
