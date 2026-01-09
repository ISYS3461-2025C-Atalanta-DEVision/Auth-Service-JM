package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.AdminUserResponse;
import com.devision.jm.auth.api.external.dto.LoginRequest;
import com.devision.jm.auth.api.external.dto.LoginResponse;

/**
 * Admin Authentication API Interface (External)
 *
 * Defines external API contract for admin authentication operations.
 *
 * Microservice Architecture (A.3.1):
 * - Auth Service handles: admin login, account activation/deactivation
 * - Profile Service handles: viewing/searching user profiles
 *
 * NOTE: viewCompanyAccount and searchAccounts moved to Profile Service
 */
public interface AdminAuthApi {

    /**
     * Admin login
     */
    LoginResponse adminLogin(LoginRequest request, String ipAddress);

    /**
     * Deactivate a company account by user ID
     * Sets account status to DEACTIVATED - user cannot login
     */
    AdminUserResponse deactivateCompany(String userId);

    /**
     * Reactivate a deactivated company account by user ID
     * Sets account status back to ACTIVE
     */
    AdminUserResponse activateCompany(String userId);

    /**
     * Delete a company account by user ID (hard delete)
     * Permanently removes the account from the system
     */
    void deleteCompany(String userId);
}
