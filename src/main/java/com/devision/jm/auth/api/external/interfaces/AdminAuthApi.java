package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.ApiResponse;
import com.devision.jm.auth.api.external.dto.CompanyProfileResponse;
import com.devision.jm.auth.api.external.dto.LoginRequest;
import com.devision.jm.auth.api.external.dto.LoginResponse;

import java.util.List;

/**
 * Admin Authentication API Interface (External)
 *
 * Defines external API contract for admin operations.
 * Implements Admin Panel requirements (6.1.1, 6.1.2, 6.2.1).
 */
public interface AdminAuthApi {

    /**
     * Admin login (6.1.1)
     *
     * @param request Login credentials
     * @param ipAddress Client IP address
     * @return API response with tokens
     */
    ApiResponse<LoginResponse> adminLogin(LoginRequest request, String ipAddress);

    /**
     * View company account by ID or email (6.1.2)
     *
     * @param identifier User ID or email
     * @return Company profile
     */
    ApiResponse<CompanyProfileResponse> viewCompanyAccount(String identifier);

    /**
     * Deactivate company account (6.1.2)
     *
     * @param identifier User ID or email
     * @return API response
     */
    ApiResponse<Void> deactivateCompanyAccount(String identifier);

    /**
     * Reactivate company account
     *
     * @param identifier User ID or email
     * @return API response
     */
    ApiResponse<Void> reactivateCompanyAccount(String identifier);

    /**
     * Search accounts by name (6.2.1)
     *
     * @param searchTerm Search term
     * @return List of matching profiles
     */
    ApiResponse<List<CompanyProfileResponse>> searchAccounts(String searchTerm);
}
