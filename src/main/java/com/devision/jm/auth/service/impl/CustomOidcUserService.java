package com.devision.jm.auth.service.impl;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

/**
 * Custom OIDC User Service for Google OAuth2
 *
 * WHAT THIS SERVICE DOES:
 * Google uses OIDC (OpenID Connect) instead of plain OAuth2, so we need a separate
 * service to handle OIDC user requests. This service delegates to OAuth2AuthenticationService
 * for user management (creating/linking accounts) and then wraps the result as an OidcUser.
 *
 * WHY THIS IS NEEDED:
 * Spring Security has two different interfaces:
 * - OAuth2UserService for plain OAuth2
 * - OidcUserService for OIDC (which Google uses)
 *
 * FLOW:
 * 1. Google redirects back with authorization code
 * 2. Spring Security exchanges code for tokens
 * 3. Spring Security detects OIDC and calls THIS service
 * 4. We delegate to OAuth2AuthenticationService for user management
 * 5. We wrap the result as OidcUser and add userId attribute
 * 6. OAuth2SuccessHandler receives OidcUser with userId
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOidcUserService extends OidcUserService {

    private final OAuth2AuthenticationService oauth2AuthenticationService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        // STEP 1: Call parent to get OIDC user from Google
        OidcUser oidcUser = super.loadUser(userRequest);

        log.info("OIDC login attempt via provider: {}", userRequest.getClientRegistration().getRegistrationId());

        // STEP 2: Process the user through our custom OAuth2 service
        // This creates/links the account and returns OAuth2User with userId
        String registrationId = userRequest.getClientRegistration().getRegistrationId();

        // Extract user info from OIDC token
        String email = oidcUser.getEmail();
        String name = oidcUser.getFullName();
        String providerId = oidcUser.getSubject(); // OIDC "sub" claim

        log.info("Processing OIDC user: email={}, name={}, providerId={}", email, name, providerId);

        // STEP 3: Delegate to OAuth2AuthenticationService to process user
        // We pass the oidcUser as OAuth2User since OidcUser extends OAuth2User
        var processedUser = oauth2AuthenticationService.processOAuth2User(oidcUser, registrationId);

        // STEP 4: Get userId from processed user attributes
        String userId = (String) processedUser.getAttributes().get("userId");

        log.info("OIDC user processed successfully with userId: {}", userId);

        // STEP 5: Create new OidcUser with userId attribute
        // The processedUser already has userId in its attributes, but it's an OAuth2User, not OidcUser
        // We need to create a custom OidcUser that includes the userId attribute

        // Create modified claims that include userId
        Map<String, Object> modifiedClaims = new HashMap<>(oidcUser.getClaims());
        modifiedClaims.put("userId", userId);

        // Create custom OidcUserInfo with modified claims
        var userInfo = new org.springframework.security.oauth2.core.oidc.OidcUserInfo(modifiedClaims);

        // Return OidcUser with updated attributes including userId
        return new DefaultOidcUser(
            oidcUser.getAuthorities(),
            oidcUser.getIdToken(),
            userInfo,
            "email" // nameAttributeKey
        );
    }
}
