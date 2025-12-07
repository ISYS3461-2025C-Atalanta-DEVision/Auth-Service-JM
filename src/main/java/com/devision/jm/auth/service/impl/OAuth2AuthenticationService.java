package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.event.AuthEventPublisher;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import com.devision.jm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;

/**
 * OAuth2 Authentication Service
 *
 * Handles Google SSO authentication (1.3.1, 2.3.1).
 * - Registers new SSO users automatically
 * - Links existing accounts if email matches
 * - Generates JWT tokens for authenticated users
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2AuthenticationService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final AuthEventPublisher eventPublisher;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("OAuth2 login attempt via provider: {}", registrationId);

        return processOAuth2User(oauth2User, registrationId);
    }

    /**
     * Process OAuth2 user - register if new, update if existing
     */
    private OAuth2User processOAuth2User(OAuth2User oauth2User, String registrationId) {
        Map<String, Object> attributes = oauth2User.getAttributes();

        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String providerId = (String) attributes.get("sub"); // Google's unique ID

        if (email == null) {
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        log.debug("Processing OAuth2 user: email={}, provider={}", email, registrationId);

        // Check if user exists
        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);

        if (existingUser.isPresent()) {
            User user = existingUser.get();

            // Check if user was registered with local auth (1.3.2 - account linking)
            if (user.getAuthProvider() == AuthProvider.LOCAL) {
                log.info("Linking local account to Google SSO: {}", email);
                user.setAuthProvider(AuthProvider.GOOGLE);
                user.setProviderId(providerId);
                // SSO users are automatically activated
                if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
                    user.setStatus(AccountStatus.ACTIVE);
                }
                userRepository.save(user);
            }

            // Update last login
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            log.info("OAuth2 login successful for existing user: {}", email);
            return oauth2User;
        }

        // Register new SSO user (1.3.1 - Company Registration via Google SSO)
        User newUser = createSsoUser(email, name, providerId, registrationId);
        userRepository.save(newUser);

        // Publish USER_REGISTERED event
        eventPublisher.publishUserRegistered(newUser);

        log.info("New SSO user registered: {}", email);
        return oauth2User;
    }

    /**
     * Create new user from SSO data (1.3.1)
     */
    private User createSsoUser(String email, String name, String providerId, String provider) {
        return User.builder()
                .email(email)
                .companyName(name != null ? name : email.split("@")[0])
                .authProvider(AuthProvider.valueOf(provider.toUpperCase()))
                .providerId(providerId)
                .role(Role.COMPANY)
                .status(AccountStatus.ACTIVE) // SSO users are auto-activated
                .failedLoginAttempts(0)
                .build();
    }

    /**
     * Generate tokens for OAuth2 authenticated user (called from success handler)
     */
    @Transactional
    public TokenInternalDto generateTokensForOAuth2User(String email, String ipAddress, String deviceInfo) {
        User user = userRepository.findByEmailIgnoreCase(email)
                .orElseThrow(() -> new OAuth2AuthenticationException("User not found after OAuth2 authentication"));

        // Update last login
        user.setLastLogin(LocalDateTime.now());
        userRepository.save(user);

        // Publish login success event
        eventPublisher.publishLoginSuccess(user, ipAddress, deviceInfo);

        // Generate JWT tokens
        return tokenService.generateTokens(
                user.getId(),
                user.getEmail(),
                user.getRole().name(),
                ipAddress,
                deviceInfo
        );
    }
}
