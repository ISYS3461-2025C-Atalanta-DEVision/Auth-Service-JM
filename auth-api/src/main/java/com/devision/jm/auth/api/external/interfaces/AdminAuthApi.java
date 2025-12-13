package com.devision.jm.auth.api.external.interfaces;

import com.devision.jm.auth.api.external.dto.CompanyProfileResponse;
import com.devision.jm.auth.api.external.dto.LoginRequest;
import com.devision.jm.auth.api.external.dto.LoginResponse;

import java.util.List;

/**
 * Admin Authentication API Interface (External)
 *
 * Defines external API contract for admin operations.
 */
public interface AdminAuthApi {

    LoginResponse adminLogin(LoginRequest request, String ipAddress);

    CompanyProfileResponse viewCompanyAccount(String identifier);

    void deactivateCompanyAccount(String identifier);

    void reactivateCompanyAccount(String identifier);

    List<CompanyProfileResponse> searchAccounts(String searchTerm);
}
