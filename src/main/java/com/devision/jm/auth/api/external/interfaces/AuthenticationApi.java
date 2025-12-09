package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.*;

/**
 * Authentication API Interface (External)
 *
 * Defines external API contract for authentication operations.
 * These APIs are accessible by other modules (A.2.3, A.2.4).
 */
public interface AuthenticationApi {

    CompanyProfileResponse registerCompany(CompanyRegistrationRequest request);

    LoginResponse login(LoginRequest request, String ipAddress);

    LoginResponse refreshToken(RefreshTokenRequest request);

    void logout(String accessToken, String refreshToken);

    void activateAccount(String token);

    void requestPasswordReset(String email);

    void resetPassword(String token, String newPassword);

    void changePassword(String userId, PasswordChangeRequest request);

    boolean validateToken(String token);
}
