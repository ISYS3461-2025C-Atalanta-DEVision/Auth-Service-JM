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
 * This is the Business Logic Layer (A.2.2) for authentication.
 *
 * Implements requirements:
 * - Company Registration (1.1.1 - 1.3.3)
 * - Company Login (2.1.1 - 2.3.3)
 * - JWE Token management (2.2.1)
 * - Brute-force protection via Redis (2.2.2)
 * - Token revocation (2.2.3, 2.3.2)
 */
@Slf4j  // Lombok: auto-generates logger field 'log'
@Service  // Marks as Spring service bean for dependency injection
@RequiredArgsConstructor  // Lombok: generates constructor for all final fields
public class AuthenticationServiceImpl implements AuthenticationApi {

    // ==================== BRUTE-FORCE PROTECTION CONSTANTS (2.2.2) ====================
    // Block authentication after 5 failed attempts within 60 seconds
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_SECONDS = 60;
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";

    // ==================== DEPENDENCIES (injected via constructor) ====================
    private final UserRepository userRepository;        // Data access for User entity
    private final UserMapper userMapper;                // MapStruct mapper for DTO conversions
    private final PasswordEncoder passwordEncoder;       // BCrypt password hashing
    private final TokenService tokenService;            // JWE token generation/validation
    private final AuthEventPublisher eventPublisher;    // Publishes events (emails, audit)
    private final RedisTemplate<String, String> redisTemplate;  // Redis for brute-force tracking

    // ==================== COMPANY REGISTRATION (1.1.1 - 1.3.3) ====================

    /**
     * Register a new company account (Requirement 1.1.1)
     *
     * Flow:
     * 1. Validate country from predefined list (1.24)
     * 2. Check email uniqueness (1.1.2)
     * 3. Create user with PENDING_ACTIVATION status
     * 4. Generate activation token (1.1.3)
     * 5. Send activation email via event publisher
     *
     * @param request Registration data (email, password, country, etc.)
     * @return Company profile response with user ID and details
     */
    @Override
    @Transactional  // Ensures database operations are atomic (all succeed or all rollback)
    public CompanyProfileResponse registerCompany(CompanyRegistrationRequest request) {
        log.info("Registering new company with email: {}", request.getEmail());

        // Validate country from predefined dropdown list (Requirement 1.24)
        if (!CountryValidator.isValidCountry(request.getCountry())) {
            throw new AuthException("Invalid country. Please select a valid country.",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "INVALID_COUNTRY");
        }

        // Check email uniqueness - no two companies can share same email (Requirement 1.1.2)
        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }

        // Create user entity from registration request using MapStruct mapper
        User user = userMapper.registrationRequestToEntity(request);

        // Hash password using BCrypt (never store plain text passwords!)
        user.setPasswordHash(passwordEncoder.encode(request.getPassword()));

        // Set default values for new registration
        user.setRole(Role.COMPANY);                          // All registrations are COMPANY role
        user.setStatus(AccountStatus.PENDING_ACTIVATION);    // Must activate via email (1.1.3)
        user.setAuthProvider(AuthProvider.LOCAL);            // Not SSO registration
        user.setFailedLoginAttempts(0);                      // Initialize login attempt counter

        // Generate activation token for email verification (Requirement 1.1.3)
        // Token is a random UUID, expires in 24 hours
        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);
        user.setActivationTokenExpiry(LocalDateTime.now().plusHours(24));

        // Persist user to MongoDB
        User savedUser = userRepository.save(user);
        log.info("Company registered successfully: {}", savedUser.getId());

        // Publish USER_REGISTERED event - triggers activation email (1.1.3)
        // Event is handled asynchronously by AuthEventPublisher
        eventPublisher.publishUserRegistered(savedUser);

        // Convert entity to response DTO (hides sensitive fields like password hash)
        return userMapper.toCompanyProfileResponse(savedUser);
    }

    // ==================== COMPANY LOGIN (2.1.1 - 2.3.3) ====================

    /**
     * Authenticate company and generate JWE tokens (Requirement 2.1.1, 2.2.1)
     *
     * Flow:
     * 1. Check brute-force protection (2.2.2)
     * 2. Find user by email
     * 3. Validate account status (must be ACTIVE)
     * 4. Verify password
     * 5. Generate JWE access token + refresh token (2.2.1, 2.3.3)
     * 6. Return tokens and user info
     *
     * @param request Login credentials (email, password)
     * @param ipAddress Client IP for audit logging and brute-force tracking
     * @return Login response with JWE tokens and user info
     */
    @Override
    @Transactional  // Atomic: updates failed attempts and last login together
    public LoginResponse login(LoginRequest request, String ipAddress) {
        log.info("Login attempt for email: {}", request.getEmail());

        // ===== STEP 1: Check brute-force protection (Requirement 2.2.2) =====
        // Block if 5+ failed attempts within 60 seconds
        if (isAccountTemporarilyLocked(request.getEmail())) {
            long remainingLockTime = getRemainingLockTime(request.getEmail());
            throw new AccountLockedException(remainingLockTime);
        }

        // ===== STEP 2: Find user by email =====
        User user = userRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> {
                    // Record failed attempt even for non-existent users (prevents enumeration)
                    recordFailedAttempt(request.getEmail());
                    eventPublisher.publishLoginFailed(request.getEmail(), "USER_NOT_FOUND", ipAddress);
                    // Return generic error message (don't reveal if email exists)
                    return new InvalidCredentialsException();
                });

        // ===== STEP 3: Check SSO restriction (Requirement 1.3.2) =====
        // SSO users cannot login with password - they must use their OAuth provider
        if (user.isSsoUser()) {
            throw new InvalidCredentialsException(
                    "This account uses SSO authentication. Please login via " + user.getAuthProvider());
        }

        // ===== STEP 4: Check account status =====
        // Account must be activated before login (Requirement 1.1.3)
        if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
            throw new AccountNotActivatedException();
        }

        // Deactivated accounts cannot login
        if (user.getStatus() == AccountStatus.DEACTIVATED) {
            throw new AuthException("Account has been deactivated. Please contact support.",
                    org.springframework.http.HttpStatus.FORBIDDEN, "ACCOUNT_DEACTIVATED");
        }

        // Check database-level account lock (backup to Redis)
        if (user.isAccountLocked()) {
            long remainingSeconds = Duration.between(LocalDateTime.now(), user.getLockedUntil()).getSeconds();
            throw new AccountLockedException(remainingSeconds);
        }

        // ===== STEP 5: Validate password =====
        // BCrypt comparison - timing-safe to prevent timing attacks
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            recordFailedAttempt(request.getEmail());      // Track in Redis
            handleFailedLogin(user);                       // Track in database
            eventPublisher.publishLoginFailed(request.getEmail(), "INVALID_PASSWORD", ipAddress);
            throw new InvalidCredentialsException();       // Generic error (don't reveal which field is wrong)
        }

        // ===== STEP 6: Successful login - reset counters =====
        resetFailedAttempts(request.getEmail());  // Clear Redis counter
        user.resetFailedLoginAttempts();          // Clear database counter
        user.setLastLogin(LocalDateTime.now());   // Update last login timestamp
        userRepository.save(user);

        // ===== STEP 7: Generate JWE tokens (Requirement 2.2.1, 2.3.3) =====
        // Access token: short-lived (15 min), encrypted, contains user claims
        // Refresh token: long-lived (7 days), stored in database
        TokenInternalDto tokens = tokenService.generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                ipAddress,
                request.getDeviceInfo()
        );

        // Publish LOGIN_SUCCESS event for audit logging
        eventPublisher.publishLoginSuccess(user, ipAddress, request.getDeviceInfo());

        // ===== STEP 8: Build response =====
        LoginResponse response = LoginResponse.builder()
                .accessToken(tokens.getAccessToken())      // JWE encrypted token
                .refreshToken(tokens.getRefreshToken())    // UUID for token rotation
                .tokenType("Bearer")                       // Standard OAuth2 token type
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

    // ==================== TOKEN REFRESH (2.3.3) ====================

    /**
     * Refresh access token using refresh token (Requirement 2.3.3)
     *
     * Implements token rotation: old refresh token is revoked, new pair is issued.
     * This limits the damage if a refresh token is compromised.
     *
     * @param request Contains the refresh token
     * @return New access token and refresh token pair
     */
    @Override
    @Transactional
    public LoginResponse refreshToken(RefreshTokenRequest request) {
        log.debug("Token refresh attempt");

        // Delegate to TokenService - handles validation and rotation
        TokenInternalDto newTokens = tokenService.refreshTokens(request.getRefreshToken())
                .orElseThrow(() -> new InvalidTokenException("Failed to refresh token"));

        // Return new token pair (old refresh token has been revoked)
        return LoginResponse.builder()
                .accessToken(newTokens.getAccessToken())
                .refreshToken(newTokens.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(Duration.between(LocalDateTime.now(), newTokens.getAccessTokenExpiry()).getSeconds())
                .refreshExpiresIn(Duration.between(LocalDateTime.now(), newTokens.getRefreshTokenExpiry()).getSeconds())
                .build();
    }

    // ==================== LOGOUT (2.2.3) ====================

    /**
     * Logout user by revoking tokens (Requirement 2.2.3)
     *
     * Revokes both access token (via Redis blacklist) and refresh token (via database).
     * This ensures tokens cannot be used even if they haven't expired.
     *
     * @param accessToken JWT access token to revoke (added to Redis blacklist)
     * @param refreshToken Refresh token to revoke (marked invalid in database)
     */
    @Override
    @Transactional
    public void logout(String accessToken, String refreshToken) {
        log.info("Logout request");

        // Revoke access token by adding to Redis blacklist (Requirement 2.2.3, 2.3.2)
        // Token will be rejected by JwtAuthenticationFilter until it naturally expires
        if (accessToken != null) {
            tokenService.revokeAccessToken(accessToken);
        }

        // Revoke refresh token by marking as revoked in database
        if (refreshToken != null) {
            tokenService.revokeRefreshToken(refreshToken);
        }
    }

    // ==================== ACCOUNT ACTIVATION (1.1.3) ====================

    /**
     * Activate account via email link (Requirement 1.1.3)
     *
     * User clicks link in activation email, which calls this endpoint.
     * Changes account status from PENDING_ACTIVATION to ACTIVE.
     *
     * @param token Activation token from email link
     */
    @Override
    @Transactional
    public void activateAccount(String token) {
        log.info("Account activation attempt with token");

        // Find user by activation token
        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid activation token"));

        // Check if token has expired (24 hours validity)
        if (user.getActivationTokenExpiry() != null &&
            user.getActivationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Activation");
        }

        // Activate the account
        user.setStatus(AccountStatus.ACTIVE);
        user.setActivationToken(null);           // Clear token (one-time use)
        user.setActivationTokenExpiry(null);
        userRepository.save(user);

        // Publish event - triggers welcome email
        eventPublisher.publishUserActivated(user);

        log.info("Account activated successfully: {}", user.getEmail());
    }

    // ==================== PASSWORD RESET ====================

    /**
     * Request password reset email
     *
     * Generates a reset token and sends email with reset link.
     * Always returns success to prevent email enumeration attacks.
     *
     * @param email Email address to send reset link to
     */
    @Override
    @Transactional
    public void requestPasswordReset(String email) {
        log.info("Password reset request for email: {}", email);

        // Only process if user exists (but always return success)
        userRepository.findByEmailIgnoreCase(email).ifPresent(user -> {
            // SSO users cannot reset password (they don't have one)
            if (!user.isSsoUser()) {
                // Generate reset token (valid for 1 hour)
                String resetToken = UUID.randomUUID().toString();
                user.setPasswordResetToken(resetToken);
                user.setPasswordResetTokenExpiry(LocalDateTime.now().plusHours(1));
                userRepository.save(user);

                // Send password reset email
                eventPublisher.publishPasswordResetRequested(user, resetToken);
            }
        });
        // Always returns void - don't reveal if email exists (security best practice)
    }

    /**
     * Reset password using token from email
     *
     * @param token Reset token from email link
     * @param newPassword New password to set
     */
    @Override
    @Transactional
    public void resetPassword(String token, String newPassword) {
        log.info("Password reset attempt with token");

        // Find user by reset token
        User user = userRepository.findByPasswordResetToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid password reset token"));

        // Check if token has expired (1 hour validity)
        if (user.getPasswordResetTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Password reset");
        }

        // Update password (hash it first!)
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);         // Clear token (one-time use)
        user.setPasswordResetTokenExpiry(null);
        user.setLastPasswordChange(LocalDateTime.now());

        // Security: Revoke all existing tokens (force re-login on all devices)
        tokenService.revokeAllUserTokens(user.getId());

        userRepository.save(user);

        // Send confirmation email
        eventPublisher.publishPasswordResetCompleted(user);

        log.info("Password reset successful for user: {}", user.getEmail());
    }

    /**
     * Change password for authenticated user
     *
     * Requires current password verification before allowing change.
     *
     * @param userId ID of authenticated user (from JWT)
     * @param request Contains current password, new password, and confirmation
     */
    @Override
    @Transactional
    public void changePassword(String userId, PasswordChangeRequest request) {
        log.info("Password change request for user: {}", userId);

        // Validate new password matches confirmation
        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new AuthException("New password and confirmation do not match",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "PASSWORD_MISMATCH");
        }

        // Find user
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException("User not found",
                        org.springframework.http.HttpStatus.NOT_FOUND, "USER_NOT_FOUND"));

        // SSO users cannot change password (Requirement 1.3.2)
        if (user.isSsoUser()) {
            throw new AuthException("SSO users cannot change password. Please use your SSO provider.",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "SSO_PASSWORD_CHANGE_NOT_ALLOWED");
        }

        // Verify current password before allowing change
        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPasswordHash())) {
            throw new InvalidCredentialsException("Current password is incorrect");
        }

        // Update to new password
        user.setPasswordHash(passwordEncoder.encode(request.getNewPassword()));
        user.setLastPasswordChange(LocalDateTime.now());
        userRepository.save(user);

        // Send confirmation email
        eventPublisher.publishNotificationEvent(
                com.devision.jm.auth.event.AuthEvent.EventType.PASSWORD_CHANGED,
                user,
                Map.of("changeType", "USER_INITIATED")
        );

        log.info("Password changed successfully for user: {}", user.getEmail());
    }

    // ==================== TOKEN VALIDATION ====================

    /**
     * Validate access token (used by API Gateway)
     *
     * @param token JWE access token to validate
     * @return true if token is valid and not revoked
     */
    @Override
    public boolean validateToken(String token) {
        return tokenService.validateAccessToken(token);
    }

    // ==================== BRUTE-FORCE PROTECTION (2.2.2) ====================
    // Implements: "blocking the authentication after 5 failed login attempts within 60 seconds"

    /**
     * Record failed login attempt in Redis
     * Counter increments with each failure, auto-expires after 60 seconds
     */
    private void recordFailedAttempt(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();

            // Increment counter (creates key if doesn't exist)
            Long attempts = redisTemplate.opsForValue().increment(key);

            // Set expiration on first attempt (60 second window)
            if (attempts == 1) {
                redisTemplate.expire(key, Duration.ofSeconds(LOCK_DURATION_SECONDS));
            }

            // Log warning when threshold reached
            if (attempts != null && attempts >= MAX_FAILED_ATTEMPTS) {
                log.warn("Account locked due to {} failed attempts: {}", attempts, email);
            }
        } catch (Exception e) {
            // Don't fail login if Redis is unavailable
            log.error("Failed to record failed attempt: {}", e.getMessage());
        }
    }

    /**
     * Check if account is temporarily locked due to brute-force protection
     *
     * @return true if 5+ failed attempts in last 60 seconds
     */
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
        return false;  // Allow login if Redis unavailable
    }

    /**
     * Get remaining lock time in seconds
     */
    private long getRemainingLockTime(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            Long ttl = redisTemplate.getExpire(key);
            return ttl != null && ttl > 0 ? ttl : 0;
        } catch (Exception e) {
            return LOCK_DURATION_SECONDS;  // Assume full lock time if Redis unavailable
        }
    }

    /**
     * Reset failed attempts counter on successful login
     */
    private void resetFailedAttempts(String email) {
        try {
            String key = FAILED_ATTEMPTS_PREFIX + email.toLowerCase();
            redisTemplate.delete(key);
        } catch (Exception e) {
            log.error("Failed to reset failed attempts: {}", e.getMessage());
        }
    }

    /**
     * Handle failed login in database (backup to Redis)
     * Also locks account in database after 5 failures
     */
    private void handleFailedLogin(User user) {
        user.incrementFailedLoginAttempts();

        // Lock account in database (backup if Redis fails)
        if (user.getFailedLoginAttempts() >= MAX_FAILED_ATTEMPTS) {
            user.setLockedUntil(LocalDateTime.now().plusSeconds(LOCK_DURATION_SECONDS));
            log.warn("Account locked in database for user: {}", user.getEmail());
        }

        userRepository.save(user);
    }

}
