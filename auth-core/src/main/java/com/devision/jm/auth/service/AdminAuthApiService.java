package com.devision.jm.auth.service;

import com.devision.jm.auth.api.external.dto.AdminUserResponse;
import com.devision.jm.auth.api.external.dto.LoginRequest;
import com.devision.jm.auth.api.external.dto.LoginResponse;
import com.devision.jm.auth.api.external.interfaces.AdminAuthApi;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Admin Auth API Service
 *
 * Implements admin operations for company account management.
 * Used by JA team via external API key authentication.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthApiService implements AdminAuthApi {

    private final UserRepository userRepository;
    private final AuthenticationApi authenticationService;

    @Override
    public LoginResponse adminLogin(LoginRequest request, String ipAddress) {
        return authenticationService.login(request, ipAddress);
    }

    @Override
    public AdminUserResponse deactivateCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.setStatus(AccountStatus.DEACTIVATED);
        userRepository.save(user);

        log.info("Company deactivated: userId={}, email={}", userId, user.getEmail());

        return AdminUserResponse.builder()
                .userId(userId)
                .email(user.getEmail())
                .status(AccountStatus.DEACTIVATED.name())
                .message("Company account deactivated successfully")
                .build();
    }

    @Override
    public AdminUserResponse activateCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.setStatus(AccountStatus.ACTIVE);
        userRepository.save(user);

        log.info("Company activated: userId={}, email={}", userId, user.getEmail());

        return AdminUserResponse.builder()
                .userId(userId)
                .email(user.getEmail())
                .status(AccountStatus.ACTIVE.name())
                .message("Company account activated successfully")
                .build();
    }

    @Override
    public void deleteCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        String email = user.getEmail();
        userRepository.delete(user);

        log.info("Company deleted: userId={}, email={}", userId, email);
    }
}
