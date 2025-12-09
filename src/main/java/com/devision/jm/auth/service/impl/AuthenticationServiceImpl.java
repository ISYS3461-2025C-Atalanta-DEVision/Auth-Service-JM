package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.external.dto.*;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.event.AuthEventPublisher;
import com.devision.jm.auth.exception.*;
import com.devision.jm.auth.mapper.UserMapper;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import com.devision.jm.auth.repository.UserRepository;
import com.devision.jm.auth.util.CountryValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.UUID;

/**
 * Authentication Service Implementation
 *
 * Main service implementing external AuthenticationApi interface.
 * Handles all authentication-related business logic.
 *
 * Implements:
 * - Company Registration (1.1.1 - 1.3.3)
 * - Company Login (2.1.1 - 2.3.3)
 * - Token management
 * - Brute-force protection (2.2.2)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationApi {

    // Brute-force protection constants (2.2.2)
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_SECONDS = 60;
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";

    private final UserRepository userRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final AuthEventPublisher eventPublisher;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    @Transactional
    public CompanyProfileResponse registerCompany(CompanyRegistrationRequest request) {
        log.info("Registering new company with email: {}", request.getEmail());

        // Validate country (1.24 - must be from dropdown/predefined list)
        if (!CountryValidator.isValidCountry(request.getCountry())) {
            throw new AuthException("Invalid country. Please select a valid country.",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "INVALID_COUNTRY");
        }

        // Check email uniqueness (1.1.2)
        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }

        // Create user entity
        User user = userMapper.registrationRequestToEntity(request);
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));
        user.setRole(Role.COMPANY);
        user.setStatus(AccountStatus.PENDING_ACTIVATION);
        user.setAuthProvider(AuthProvider.LOCAL);
        user.setFailedLoginAttempts(0);

        // Generate activation token (1.1.3)
        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);
        user.setActivationTokenExpiry(LocalDateTime.now().plusHours(24));

        // Save user
        User savedUser = userRepository.save(user);
        log.info("Company registered successfully: {}", savedUser.getId());

        // Publish USER_REGISTERED event (triggers welcome email and profile creation)
        eventPublisher.publishUserRegistered(savedUser);

        // Return response
        return userMapper.toCompanyProfileResponse(savedUser);
    }

    @Override
    @Transactional
    public LoginResponse login(LoginRequest request, String ipAddress) {
        log.info("Login attempt for email: {}", request.getEmail());

        // Check brute-force protection (2.2.2)
        if (isAccountTemporarilyLocked(request.getEmail())) {
            long remainingLockTime = getRemainingLockTime(request.getEmail());
            throw new AccountLockedException(remainingLockTime);
        }

        // Find user
        User user = userRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> {
                    recordFailedAttempt(request.getEmail());
                    eventPublisher.publishLoginFailed(request.getEmail(), "USER_NOT_FOUND", ipAddress);
                    return new InvalidCredentialsException();
                });

        // Check if SSO user trying to login with password (1.3.2)
        if (user.isSsoUser()) {
            throw new InvalidCredentialsException("This account uses SSO authentication. Please login via " + user.getAuthProvider());
        }

        // Check account status
        if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
            throw new AccountNotActivatedException();
        }

        if (user.getStatus() == AccountStatus.DEACTIVATED) {
            throw new AuthException("Account has been deactivated. Please contact support.",
                    org.springframework.http.HttpStatus.FORBIDDEN, "ACCOUNT_DEACTIVATED");
        }

        // Check if account is locked in database
        if (user.isAccountLocked()) {
            long remainingSeconds = Duration.between(LocalDateTime.now(), user.getLockedUntil()).getSeconds();
            throw new AccountLockedException(remainingSeconds);
        }

        // Validate password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            recordFailedAttempt(request.getEmail());
            handleFailedLogin(user);
            eventPublisher.publishLoginFailed(request.getEmail(), "INVALID_PASSWORD", ipAddress);
            throw new InvalidCredentialsException();
        }

        // Successful login - reset failed attempts
        resetFailedAttempts(request.getEmail());
        user.resetFailedLoginAttempts();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        // Generate tokens
        TokenInternalDto tokens = tokenService.generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                ipAddress,
                request.getDeviceInfo()
        );

        // Publish LOGIN_SUCCESS event (updates profile last login, audit logging)
        eventPublisher.publishLoginSuccess(user, ipAddress, request.getDeviceInfo());

        // Build response
        LoginResponse response = LoginResponse.builder()
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(Duration.between(LocalDateTime.now(), tokens.getAccessTokenExpiry()).getSeconds())
                .refreshExpiresIn(Duration.between(LocalDateTime.now(), tokens.getRefreshTokenExpiry()).getSeconds())
                .user(LoginResponse.UserInfo.builder()
                        .id(user.getId().toString())
                        .email(user.getEmail())
                        .role(user.getRole().name())
                        .companyName(user.getCompanyName())
                        .country(user.getCountry())
                        .build())
                .build();

        log.info("Login successful for user: {}", user.getEmail());
        return response;
    }

    @Override
    @Transactional
    public LoginResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Token refresh attempt");

        TokenInternalDto newTokens = tokenService.refreshTokens(request.getRefreshToken())
                .orElseThrow(() -> new InvalidTokenException("Failed to refresh token"));

        return LoginResponse.builder()
                .accessToken(newTokens.getAccessToken())
                .refreshToken(newTokens.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(Duration.between(LocalDateTime.now(), newTokens.getAccessTokenExpiry()).getSeconds())
                .refreshExpiresIn(Duration.between(LocalDateTime.now(), newTokens.getRefreshTokenExpiry()).getSeconds())
                .build();
    }

    @Override
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        log.info("Logout request");

        // Revoke access token (add to Redis blacklist) - 2.2.3
        if (accessToken != null) {
            tokenService.revokeAccessToken(accessToken);
        }

        // Revoke refresh token
        if (refreshToken != null) {
            tokenService.revokeRefreshToken(refreshToken);
        }
    }

    @Override
    @Transactional
    public void activateAccount(String token) {
        log.info("Account activation attempt with token");

        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid activation token"));

        // Check token expiry
        if (user.getActivationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Activation");
        }

        // Activate account
        user.setStatus(AccountStatus.ACTIVE);
        user.setActivationToken(null);
        user.setActivationTokenExpiry(null);
        userRepository.save(user);

        // Publish USER_ACTIVATED event
        eventPublisher.publishUserActivated(user);

        log.info("Account activated successfully: {}", user.getEmail());
    }

    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        log.info("Password reset request for email: {}", email);

        userRepository.findByEmailIgnoreCase(email).ifPresent(user -> {
            // Don't allow password reset for SSO users
            if (!user.isSsoUser()) {
                String resetToken = UUID.randomUUID().toString();
                user.setPasswordResetToken(resetToken);
                user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
                userRepository.save(user);

                // Publish PASSWORD_RESET_REQUESTED event (triggers email)
                eventPublisher.publishPasswordResetRequested(user, resetToken);
            }
        });
        // Always returns void to prevent email enumeration
    }

    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        log.info("Password reset attempt with token");

        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid password reset token"));

        // Check token expiry
        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Password reset");
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiry(null);
        user.setLastPasswordChange(LocalDateTime.now());

        // Revoke all existing tokens for security
        tokenService.revokeAllUserTokens(user.getId());

        userRepository.save(user);

        // Publish PASSWORD_RESET_COMPLETED event (triggers confirmation email, audit)
        eventPublisher.publishPasswordResetCompleted(user);

        log.info("Password reset successful for user: {}", user.getEmail());
    }

    @Override
    @Transactional
    public void changePassword(String userId, PasswordChangeRequest request) {
        log.info("Password change request for user: {}", userId);

        // Validate new password matches confirmation
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new AuthException("New password and confirmation do not match",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "PASSWORD_MISMATCH");
        }

        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found",
                        org.springframework.http.HttpStatus.NOT_FOUND, "USER_NOT_FOUND"));

        // SSO users cannot change password (1.3.2 - SSO users cannot use password for system access)
        if (user.isSsoUser()) {
            throw new AuthException("SSO users cannot change password. Please use your SSO provider.",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "SSO_PASSWORD_CHANGE_NOT_ALLOWED");
        }

        // Verify current password
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Update password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);

        // Publish password change notification event
        eventPublisher.publishNotificationEvent(
                com.devision.jm.auth.event.AuthEvent.EventType.PASSWORD_CHANGED,
                user,
                Map.of("changeType", "USER_INITIATED")
        );

        log.info("Password changed successfully for user: {}", user.getEmail());
    }

    @Override
    public boolean validateToken(String token) {
        return tokenService.validateAccessToken(token);
    }

    // ==================== Brute-force Protection (2.2.2) ====================

    private void recordFailedAttempt(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            Long attempts = redisTemplate.opsForValue().increment(key);

            if (attempts == 1) {
                redisTemplate.expire(key, Duration.ofSeconds(LOCK_DURATION_SECONDS));
            }

            if (attempts != null && attempts >= MAX_FAILED_ATTEMPTS) {
                log.warn("Account locked due to {} failed attempts: {}", attempts, email);
            }
        } catch (Exception e) {
            log.error("Failed to record failed attempt: {}", e.getMessage());
        }
    }

    private boolean isAccountTemporarilyLocked(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            String value = redisTemplate.opsForValue().get(key);
            if (value != null) {
                int attempts = Integer.parseInt(value);
                return attempts >= MAX_FAILED_ATTEMPTS;
            }
        } catch (Exception e) {
            log.error("Failed to check account lock status: {}", e.getMessage());
        }
        return false;
    }

    private long getRemainingLockTime(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            Long ttl = redisTemplate.getExpire(key);
            return ttl != null && ttl > 0 ? ttl : 0;
        } catch (Exception e) {
            return LOCK_DURATION_SECONDS;
        }
    }

    private void resetFailedAttempts(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            redisTemplate.delete(key);
        } catch (Exception e) {
            log.error("Failed to reset failed attempts: {}", e.getMessage());
        }
    }

    private void handleFailedLogin(User user) {
        user.incrementFailedLoginAttempts();

        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(LocalDateTime.now().plusSeconds(LOCK_DURATION_SECONDS));
            log.warn("Account locked in database for user: {}", user.getEmail());
        }

        userRepository.save(user);
    }

}
