package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.*;

/**
 * Authentication API Interface (External)
 *
 * Defines external API contract for authentication operations.
 * These APIs are accessible by other modules (A.2.3, A.2.4).
 *
 * Implements:
 * - Company Registration (1.1.1 - 1.3.3)
 * - Company Login (2.1.1 - 2.3.3)
 * - Token management
 */
public interface AuthenticationApi {

    /**
     * Register a new company account
     *
     * @param request Registration details
     * @return API response with registration result
     */
    ApiResponse<CompanyProfileResponse> registerCompany(CompanyRegistrationRequest request);

    /**
     * Authenticate company user
     *
     * @param request Login credentials
     * @param ipAddress Client IP address for security tracking
     * @return API response with tokens and user info
     */
    ApiResponse<LoginResponse> login(LoginRequest request, String ipAddress);

    /**
     * Refresh access token using refresh token
     *
     * @param request Refresh token
     * @return API response with new tokens
     */
    ApiResponse<LoginResponse> refreshToken(RefreshTokenRequest request);

    /**
     * Logout user and invalidate tokens
     *
     * @param accessToken Current access token
     * @param refreshToken Current refresh token
     * @return API response
     */
    ApiResponse<Void> logout(String accessToken, String refreshToken);

    /**
     * Activate account via activation token
     *
     * @param token Activation token from email
     * @return API response
     */
    ApiResponse<Void> activateAccount(String token);

    /**
     * Request password reset
     *
     * @param email User email
     * @return API response
     */
    ApiResponse<Void> requestPasswordReset(String email);

    /**
     * Reset password using reset token
     *
     * @param token Reset token from email
     * @param newPassword New password
     * @return API response
     */
    ApiResponse<Void> resetPassword(String token, String newPassword);

    /**
     * Change password for authenticated user
     *
     * @param userId User ID
     * @param request Password change details
     * @return API response
     */
    ApiResponse<Void> changePassword(String userId, PasswordChangeRequest request);

    /**
     * Validate access token (used by API Gateway)
     *
     * @param token Access token
     * @return True if token is valid and not revoked
     */
    boolean validateToken(String token);
}
