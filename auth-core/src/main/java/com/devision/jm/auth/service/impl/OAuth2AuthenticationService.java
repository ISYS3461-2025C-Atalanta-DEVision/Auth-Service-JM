package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.dto.UserCreatedEvent;
import com.devision.jm.auth.api.internal.interfaces.KafkaProducerService;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import com.devision.jm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;

/**
 * OAuth2 Authentication Service - Google SSO User Management
 *
 * WHAT THIS SERVICE DOES:
 * This service handles the user management part of Google OAuth2 authentication.
 * It's called by Spring Security AFTER Google authentication succeeds but BEFORE
 * the success handler runs.
 *
 * Microservice Architecture (A.3.1, A.3.2):
 * - Auth Service owns: email, tokens, security fields
 * - Profile Service owns: company info, contact info
 * - Communication: Kafka events for Profile Service
 *
 * WHEN IT'S CALLED:
 * Automatically invoked by Spring Security during OAuth2 flow:
 * 1. User logs in with Google
 * 2. Spring Security exchanges authorization code for access token
 * 3. Spring Security fetches user info from Google
 * 4. → THIS SERVICE RUNS (loadUser method)
 * 5. OAuth2SuccessHandler runs (generates JWE tokens)
 *
 * KEY RESPONSIBILITIES:
 * 1. Create new user account if first-time Google login (Req 1.3.1)
 * 2. Link existing local account to Google if email matches (Req 1.3.2)
 * 3. Auto-activate SSO users (no email verification needed)
 * 4. Update last login timestamp
 * 5. Publish UserCreatedEvent to Kafka for Profile Service
 * 6. Generate JWE tokens for OAuth2 success handler
 *
 * REQUIREMENTS:
 * - Req 1.3.1: Company Registration via Google SSO
 * - Req 1.3.2: Account Linking (link local account to Google)
 * - Req 2.3.1: Google OAuth Login (Ultimo level)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2AuthenticationService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final KafkaProducerService kafkaProducerService;  // For publishing to Profile Service

    /**
     * Load OAuth2 User - Main Entry Point
     */
    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("OAuth2 login attempt via provider: {}", registrationId);
        return processOAuth2User(oauth2User, registrationId);
    }

    /**
     * Process OAuth2 User - Create New or Update Existing Account
     *
     * THREE SCENARIOS:
     * 1. NEW USER: Email doesn't exist → Create new SSO account, publish to Kafka
     * 2. EXISTING LOCAL USER: Email exists with LOCAL auth → Link to Google (Req 1.3.2)
     * 3. EXISTING SSO USER: Email exists with GOOGLE auth → Update last login
     */
    OAuth2User processOAuth2User(OAuth2User oauth2User, String registrationId) {
        Map<String, Object> attributes = oauth2User.getAttributes();

        log.debug("OAuth2 user attributes: {}", attributes);

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String providerId = (String) attributes.get("sub");
        String picture = (String) attributes.get("picture");

        if (email == null) {
            log.error("Email not provided by OAuth2 provider. Attributes: {}", attributes);
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        log.info("Processing OAuth2 user: email={}, provider={}, name={}, providerId={}",
                email, registrationId, name, providerId);

        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();

            // ACCOUNT LINKING (Req 1.3.2)
            if (user.getAuthProvider() == AuthProvider.LOCAL) {
                log.info("Linking local account to Google SSO: {}", email);
                user.setAuthProvider(AuthProvider.GOOGLE);
                user.setProviderId(providerId);

                if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
                    user.setStatus(AccountStatus.ACTIVE);
                }

                userRepository.save(user);
            }

            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            log.info("OAuth2 login successful for existing user: {} with userId: {}", email, user.getId());

            OAuth2User updatedOAuth2User = createOAuth2UserWithUserId(oauth2User, user.getId());
            return updatedOAuth2User;
        }

        // NEW USER - Register as SSO user and publish to Kafka
        User newUser = createSsoUser(email, providerId, registrationId);
        userRepository.save(newUser);

        log.info("New SSO user registered: {} with userId: {}", email, newUser.getId());

        // Publish UserCreatedEvent to Kafka for Profile Service (A.3.2)
        publishUserCreatedEvent(newUser, name, picture);

        OAuth2User updatedOAuth2User = createOAuth2UserWithUserId(oauth2User, newUser.getId());
        return updatedOAuth2User;
    }

    /**
     * Create New SSO User Account (Req 1.3.1)
     *
     * Creates User entity with auth fields only.
     * Profile data (name, etc.) is sent to Profile Service via Kafka.
     */
    private User createSsoUser(String email, String providerId, String provider) {
        return User.builder()
                .email(email)
                .authProvider(AuthProvider.valueOf(provider.toUpperCase()))
                .providerId(providerId)
                .role(Role.COMPANY)
                .status(AccountStatus.ACTIVE)  // SSO users are immediately active
                .failedLoginAttempts(0)
                .build();
    }

    /**
     * Publish UserCreatedEvent to Kafka for Profile Service
     */
    private void publishUserCreatedEvent(User user, String name, String avatarUrl) {
        try {
            UserCreatedEvent event = UserCreatedEvent.builder()
                    .userId(user.getId())
                    .email(user.getEmail())
                    .companyName(name != null ? name : user.getEmail().split("@")[0])  // Use name or email prefix
                    .country(null)  // SSO users can set country later in profile
                    .city(null)
                    .streetAddress(null)
                    .phoneNumber(null)
                    .avatarUrl(avatarUrl)  // Profile picture from Google
                    .authProvider(user.getAuthProvider().name())
                    .createdAt(LocalDateTime.now())
                    .build();

            kafkaProducerService.publishUserCreatedEvent(event);
            log.info("Published user-created event to Kafka for SSO userId: {}", user.getId());

        } catch (Exception e) {
            // Log but don't fail registration - Profile Service can recover
            log.error("Failed to publish user-created event for SSO user: {}", e.getMessage());
        }
    }

    /**
     * Create OAuth2User with userId attribute
     */
    private OAuth2User createOAuth2UserWithUserId(OAuth2User oauth2User, String userId) {
        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());
        attributes.put("userId", userId);
        Set<GrantedAuthority> authorities = new HashSet<>(oauth2User.getAuthorities());
        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    /**
     * Generate JWE Tokens for OAuth2 User
     */
    public TokenInternalDto generateTokensForOAuth2User(String userId, String ipAddress, String deviceInfo) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new OAuth2AuthenticationException("User not found after OAuth2 authentication"));

        return tokenService.generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                ipAddress,
                deviceInfo
        );
    }
}
