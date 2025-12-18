package com.devision.jm.auth.service;

import com.devision.jm.auth.api.external.dto.*;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.dto.UserCreatedEvent;
import com.devision.jm.auth.api.internal.interfaces.EmailService;
import com.devision.jm.auth.api.internal.interfaces.KafkaProducerService;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.exception.*;
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
import java.util.UUID;

/**
 * Authentication Service Implementation
 *
 * Main service implementing external AuthenticationApi interface.
 * This is the Business Logic Layer (A.2.2) for authentication.
 *
 * Microservice Architecture (A.3.1, A.3.2):
 * - Auth Service owns: email, password, tokens, security
 * - Profile Service owns: company info, contact info (via Kafka)
 *
 * Implements requirements:
 * - Company Registration (1.1.1 - 1.3.3)
 * - Company Login (2.1.1 - 2.3.3)
 * - JWE Token management (2.2.1)
 * - Brute-force protection via Redis (2.2.2)
 * - Token revocation (2.2.3, 2.3.2)
 */
@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(rollbackFor = Exception.class)
public class AuthenticationServiceImpl implements AuthenticationApi {

    // ==================== BRUTE-FORCE PROTECTION CONSTANTS (2.2.2) ====================
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final int LOCK_DURATION_SECONDS = 60;
    private static final String FAILED_ATTEMPTS_PREFIX = "failed_attempts:";

    // ==================== DEPENDENCIES ====================
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final RedisTemplate<String, String> redisTemplate;
    private final EmailService emailService;
    private final KafkaProducerService kafkaProducerService;  // For publishing to Profile Service

    // ==================== COMPANY REGISTRATION (1.1.1 - 1.3.3) ====================

    /**
     * Register a new company account (Requirement 1.1.1)
     *
     * Microservice Flow:
     * 1. Validate country from predefined list (1.24)
     * 2. Check email uniqueness (1.1.2)
     * 3. Create user in Auth DB (email, password, tokens only)
     * 4. Publish UserCreatedEvent to Kafka (A.3.2)
     * 5. Profile Service consumes event and creates profile
     * 6. Send activation email (1.1.3)
     *
     * @param request Registration data (email, password, country, etc.)
     * @return Registration response with userId
     */
    @Override
    public RegistrationResponse registerCompany(CompanyRegistrationRequest request) {
        log.info("Registering new company with email: {}", request.getEmail());

        // Validate country from predefined dropdown list (Requirement 1.24)
        if (!CountryValidator.isValidCountry(request.getCountry())) {
            throw new AuthException("Invalid country. Please select a valid country.",
                    org.springframework.http.HttpStatus.BAD_REQUEST, "INVALID_COUNTRY");
        }

        // Check email uniqueness (Requirement 1.1.2)
        if (userRepository.existsByEmailIgnoreCase(request.getEmail())) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }

        // Create user entity (auth fields only - no profile data)
        User user = User.builder()
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .role(Role.COMPANY)
                .status(AccountStatus.PENDING_ACTIVATION)
                .authProvider(AuthProvider.LOCAL)
                .failedLoginAttempts(0)
                .build();

        // Generate activation token (Requirement 1.1.3)
        String activationToken = UUID.randomUUID().toString();
        user.setActivationToken(activationToken);
        user.setActivationTokenExpiry(LocalDateTime.now().plusHours(24));

        // Save user to Auth DB
        User savedUser = userRepository.save(user);
        log.info("User created in Auth DB: {}", savedUser.getId());

        // Publish UserCreatedEvent to Kafka for Profile Service (A.3.2)
        publishUserCreatedEvent(savedUser, request);

        // Send activation email (Requirement 1.1.3)
        try {
            emailService.sendActivationEmail(savedUser, activationToken);
            log.info("Activation email sent to: {}", savedUser.getEmail());
        } catch (Exception e) {
            log.error("Failed to send activation email: {}", e.getMessage());
        }

        // Return registration response
        return RegistrationResponse.builder()
                .userId(savedUser.getId())
                .email(savedUser.getEmail())
                .message("Registration successful. Please check your email to activate your account.")
                .build();
    }

    /**
     * Publish UserCreatedEvent to Kafka for Profile Service
     */
    private void publishUserCreatedEvent(User user, CompanyRegistrationRequest request) {
        try {
            UserCreatedEvent event = UserCreatedEvent.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .companyName(request.getCompanyName())
                    .country(request.getCountry())
                    .city(request.getCity())
                    .streetAddress(request.getStreetAddress())
                    .phoneNumber(request.getPhoneNumber())
                    .authProvider(user.getAuthProvider().name())
                    .createdAt(LocalDateTime.now())
                    .build();

            kafkaProducerService.publishUserCreatedEvent(event);
            log.info("Published user-created event to Kafka for userId: {}", user.getId());

        } catch (Exception e) {
            // Log but don't fail registration - Profile Service can recover
            log.error("Failed to publish user-created event: {}", e.getMessage());
        }
    }

    // ==================== COMPANY LOGIN (2.1.1 - 2.3.3) ====================

    @Override
    public LoginResponse login(LoginRequest request, String ipAddress) {
        log.info("Login attempt for email: {}", request.getEmail());

        // Check brute-force protection (2.2.2)
        if (isAccountTemporarilyLocked(request.getEmail())) {
            long remainingLockTime = getRemainingLockTime(request.getEmail());
            throw new AccountLockedException(remainingLockTime);
        }

        // Find user by email
        User user = userRepository.findByEmailIgnoreCase(request.getEmail())
                .orElseThrow(() -> {
                    recordFailedAttempt(request.getEmail());
                    return new InvalidCredentialsException();
                });

        // Check SSO restriction (1.3.2)
        if (user.isSsoUser()) {
            throw new InvalidCredentialsException(
                    "This account uses SSO authentication. Please login via " + user.getAuthProvider());
        }

        // Check account status
        if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
            throw new AccountNotActivatedException();
        }

        if (user.getStatus() == AccountStatus.DEACTIVATED) {
            throw new AuthException("Account has been deactivated. Please contact support.",
                    org.springframework.http.HttpStatus.FORBIDDEN, "ACCOUNT_DEACTIVATED");
        }

        if (user.isAccountLocked()) {
            long remainingSeconds = Duration.between(LocalDateTime.now(), user.getLockedUntil()).getSeconds();
            throw new AccountLockedException(remainingSeconds);
        }

        // Validate password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            recordFailedAttempt(request.getEmail());
            handleFailedLogin(user);
            throw new InvalidCredentialsException();
        }

        // Successful login - reset counters
        resetFailedAttempts(request.getEmail());
        user.resetFailedLoginAttempts();
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        // Generate JWE tokens (2.2.1, 2.3.3)
        TokenInternalDto tokens = tokenService.generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                ipAddress,
                request.getDeviceInfo()
        );

        log.info("Login successful for user: {}", user.getEmail());

        return LoginResponse.builder()
                .accessToken(tokens.getAccessToken())
                .refreshToken(tokens.getRefreshToken())
                .tokenType("Bearer")
                .expiresIn(Duration.between(LocalDateTime.now(), tokens.getAccessTokenExpiry()).getSeconds())
                .refreshExpiresIn(Duration.between(LocalDateTime.now(), tokens.getRefreshTokenExpiry()).getSeconds())
                .build();
    }

    // ==================== TOKEN REFRESH (2.3.3) ====================

    @Override
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

    // ==================== LOGOUT (2.2.3) ====================

    @Override
    public void logout(String accessToken, String refreshToken) {
        log.info("Logout request");

        if (accessToken != null) {
            tokenService.revokeAccessToken(accessToken);
        }

        if (refreshToken != null) {
            tokenService.revokeRefreshToken(refreshToken);
        }
    }

    // ==================== ACCOUNT ACTIVATION (1.1.3) ====================

    @Override
    public void activateAccount(String token) {
        log.info("Account activation attempt");

        User user = userRepository.findByActivationToken(token)
                .orElseThrow(() -> new InvalidTokenException("Invalid activation token"));

        if (user.getActivationTokenExpiry() != null &&
            user.getActivationTokenExpiry().isBefore(LocalDateTime.now())) {
            throw new TokenExpiredException("Activation");
        }

        user.setStatus(AccountStatus.ACTIVE);
        user.setActivationToken(null);
        user.setActivationTokenExpiry(null);
        userRepository.save(user);

        log.info("Account activated successfully: {}", user.getEmail());
    }

    // ==================== TOKEN VALIDATION ====================

    @Override
    public boolean validateToken(String token) {
        return tokenService.validateAccessToken(token);
    }

    // ==================== BRUTE-FORCE PROTECTION (2.2.2) ====================

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
