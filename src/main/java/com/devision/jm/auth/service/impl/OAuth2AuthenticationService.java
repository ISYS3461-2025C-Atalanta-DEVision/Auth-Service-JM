package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.api.internal.interfaces.TokenService;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.model.enums.AuthProvider;
import com.devision.jm.auth.model.enums.Role;
import com.devision.jm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
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
 * WHEN IT'S CALLED:
 * Automatically invoked by Spring Security during OAuth2 flow:
 * 1. User logs in with Google
 * 2. Spring Security exchanges authorization code for access token
 * 3. Spring Security fetches user info from Google
 * 4. → THIS SERVICE RUNS (loadUser method)
 * 5. OAuth2SuccessHandler runs (generates JWT tokens)
 *
 * KEY RESPONSIBILITIES:
 * 1. Create new user account if first-time Google login (Req 1.3.1)
 * 2. Link existing local account to Google if email matches (Req 1.3.2)
 * 3. Auto-activate SSO users (no email verification needed)
 * 4. Update last login timestamp
 * 5. Publish USER_REGISTERED event to Kafka
 * 6. Generate JWT tokens for OAuth2 success handler
 *
 * INHERITANCE:
 * Extends DefaultOAuth2UserService which:
 * - Handles communication with Google's userinfo endpoint
 * - Validates OAuth2 access token
 * - Returns OAuth2User with user attributes (email, name, sub, etc.)
 *
 * CONFIGURATION:
 * Registered in SecurityConfig.java:
 * .oauth2Login(oauth2 -> oauth2.userInfoEndpoint(userInfo -> userInfo.userService(this)))
 *
 * REQUIREMENTS:
 * - Req 1.3.1: Company Registration via Google SSO
 * - Req 1.3.2: Account Linking (link local account to Google)
 * - Req 2.3.1: Google OAuth Login (Ultimo level)
 */
@Slf4j              // Lombok: auto-generates logger
@Service            // Spring: registers this as a service bean
@RequiredArgsConstructor  // Lombok: generates constructor for final fields
public class OAuth2AuthenticationService extends DefaultOAuth2UserService {

    // Repository for database operations on User entity
    private final UserRepository userRepository;

    // Service for generating JWT access and refresh tokens
    private final TokenService tokenService;

    /**
     * Load OAuth2 User - Main Entry Point
     *
     * WHEN THIS IS CALLED:
     * Automatically invoked by Spring Security after fetching user info from Google.
     * This is part of the OAuth2 authentication flow.
     *
     * WHAT HAPPENS:
     * 1. Calls parent class (DefaultOAuth2UserService) to fetch user info from Google
     * 2. Extracts provider ID (google, facebook, etc.)
     * 3. Processes the user (create new account or update existing)
     * 4. Returns OAuth2User object back to Spring Security
     *
     * PARAMETERS:
     * - userRequest: Contains OAuth2 access token and client registration details
     *
     * PARENT METHOD BEHAVIOR (super.loadUser):
     * - Makes HTTP GET request to Google's userinfo endpoint
     * - URL: https://www.googleapis.com/oauth2/v3/userinfo
     * - Header: Authorization: Bearer {access_token}
     * - Returns OAuth2User with attributes: {sub, email, name, picture, ...}
     *
     * TRANSACTION:
     * @Transactional ensures all database operations succeed or roll back together.
     * If any error occurs, user creation/update is rolled back.
     *
     * @param userRequest OAuth2UserRequest containing access token and registration
     * @return OAuth2User with user attributes from Google
     * @throws OAuth2AuthenticationException if user processing fails
     */
    @Override
    @Transactional  // All database operations in one transaction
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // STEP 1: Call parent class to fetch user info from Google
        // This makes the actual HTTP request to Google's userinfo endpoint
        OAuth2User oauth2User = super.loadUser(userRequest);

        // STEP 2: Get provider ID (e.g., "google")
        // This comes from application.yml: spring.security.oauth2.client.registration.google
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        log.info("OAuth2 login attempt via provider: {}", registrationId);

        // STEP 3: Process the user (create/update account)
        return processOAuth2User(oauth2User, registrationId);
    }

    /**
     * Process OAuth2 User - Create New or Update Existing Account
     *
     * WHAT THIS DOES:
     * Handles the user account management for OAuth2 authentication.
     * Determines whether to create a new account or link/update existing account.
     *
     * THREE SCENARIOS:
     * 1. NEW USER: Email doesn't exist → Create new SSO account (status=ACTIVE)
     * 2. EXISTING LOCAL USER: Email exists with LOCAL auth → Link to Google (Req 1.3.2)
     * 3. EXISTING SSO USER: Email exists with GOOGLE auth → Update last login
     *
     * GOOGLE USER ATTRIBUTES:
     * {
     *   "sub": "1234567890",              // Google's unique user ID (never changes)
     *   "email": "user@gmail.com",        // User's email address
     *   "name": "John Doe",               // Full name
     *   "given_name": "John",             // First name
     *   "family_name": "Doe",             // Last name
     *   "picture": "https://...",         // Profile picture URL
     *   "email_verified": true,           // Google already verified the email
     *   "locale": "en"                    // User's locale
     * }
     *
     * ACCOUNT LINKING (Req 1.3.2):
     * If a user registered with email/password (LOCAL) and then logs in with Google,
     * we automatically link their local account to Google:
     * - Change authProvider: LOCAL → GOOGLE
     * - Store providerId (Google's unique ID)
     * - Auto-activate if still PENDING_ACTIVATION
     * - User can now login with either method
     *
     * @param oauth2User OAuth2User object with Google user attributes
     * @param registrationId Provider ID (e.g., "google")
     * @return OAuth2User unchanged (needed for Spring Security flow)
     * @throws OAuth2AuthenticationException if email is null or processing fails
     *
     * NOTE: Made package-private (not private) so CustomOidcUserService can access it
     */
    OAuth2User processOAuth2User(OAuth2User oauth2User, String registrationId) {
        // STEP 1: Extract user attributes from Google
        Map<String, Object> attributes = oauth2User.getAttributes();

        log.debug("OAuth2 user attributes: {}", attributes);

        // Extract required fields from Google's response
        String email = (String) attributes.get("email");          // User's email
        String name = (String) attributes.get("name");            // Full name
        String providerId = (String) attributes.get("sub");       // Google's unique ID

        // Validate that email is provided (required field)
        if (email == null) {
            log.error("Email not provided by OAuth2 provider. Attributes: {}", attributes);
            throw new OAuth2AuthenticationException("Email not provided by OAuth2 provider");
        }

        log.info("Processing OAuth2 user: email={}, provider={}, name={}, providerId={}",
                email, registrationId, name, providerId);

        // STEP 2: Check if user already exists in database
        Optional<User> existingUser = userRepository.findByEmailIgnoreCase(email);

        if (existingUser.isPresent()) {
            // USER EXISTS - Update their account
            User user = existingUser.get();

            // SCENARIO: User registered with email/password, now logging in with Google
            // This is ACCOUNT LINKING (Req 1.3.2)
            if (user.getAuthProvider() == AuthProvider.LOCAL) {
                log.info("Linking local account to Google SSO: {}", email);

                // Update user to link Google account
                user.setAuthProvider(AuthProvider.GOOGLE);  // Change LOCAL → GOOGLE
                user.setProviderId(providerId);             // Store Google's unique ID

                // Auto-activate SSO users (no email verification needed)
                // Google already verified the email, so we trust it
                if (user.getStatus() == AccountStatus.PENDING_ACTIVATION) {
                    user.setStatus(AccountStatus.ACTIVE);
                }

                userRepository.save(user);
            }

            // Update last login timestamp for audit trail
            user.setLastLogin(LocalDateTime.now());
            userRepository.save(user);

            log.info("OAuth2 login successful for existing user: {} with userId: {}", email, user.getId());

            // Add userId to OAuth2User attributes so success handler can use it
            // This avoids querying the database again in the success handler
            OAuth2User updatedOAuth2User = createOAuth2UserWithUserId(oauth2User, user.getId());
            log.info("Created OAuth2User with userId attribute: {}", user.getId());
            return updatedOAuth2User;
        }

        // STEP 3: NEW USER - Register them as SSO user
        // This is COMPANY REGISTRATION VIA GOOGLE SSO (Req 1.3.1)
        User newUser = createSsoUser(email, name, providerId, registrationId);
        userRepository.save(newUser);

        log.info("New SSO user registered: {} with userId: {}", email, newUser.getId());

        // Add userId to OAuth2User attributes so success handler can use it
        // This avoids querying the database again in the success handler
        OAuth2User updatedOAuth2User = createOAuth2UserWithUserId(oauth2User, newUser.getId());
        log.info("Created OAuth2User with userId attribute for new user: {}", newUser.getId());
        return updatedOAuth2User;
    }

    /**
     * Create New SSO User Account (Req 1.3.1 - Company Registration via Google SSO)
     *
     * WHAT THIS DOES:
     * Creates a new User entity for first-time Google SSO users.
     *
     * KEY DIFFERENCES FROM EMAIL/PASSWORD REGISTRATION:
     * - NO password field (SSO users authenticate through Google)
     * - status = ACTIVE immediately (no email verification needed)
     * - authProvider = GOOGLE (not LOCAL)
     * - providerId = Google's unique user ID (the "sub" claim)
     * - companyName = User's name from Google (or email prefix if name not provided)
     *
     * FIELD MAPPINGS:
     * - email: From Google user info
     * - companyName: Google's "name" field OR email prefix (e.g., "john.doe" from "john.doe@gmail.com")
     * - authProvider: GOOGLE (identifies authentication method)
     * - providerId: Google's "sub" claim (unique, never changes)
     * - role: COMPANY (default role for all new users)
     * - status: ACTIVE (no activation email needed, Google already verified email)
     * - failedLoginAttempts: 0 (fresh account)
     *
     * WHAT'S NOT SET:
     * - password: null (SSO users don't have passwords)
     * - activationToken: null (not needed for SSO users)
     * - activationTokenExpiry: null (not needed for SSO users)
     *
     * @param email User's email from Google
     * @param name User's full name from Google (can be null)
     * @param providerId Google's unique user ID (the "sub" claim)
     * @param provider Provider name (e.g., "google")
     * @return User New user entity (not yet saved to database)
     */
    private User createSsoUser(String email, String name, String providerId, String provider) {
        // Use Builder pattern to create User entity
        return User.builder()
                // Email from Google (required field)
                .email(email)

                // Company name: Use Google's name OR email prefix as fallback
                // Example: "John Doe" OR "john.doe" from "john.doe@gmail.com"
                .companyName(name != null ? name : email.split("@")[0])

                // Auth provider: Convert "google" string → AuthProvider.GOOGLE enum
                .authProvider(AuthProvider.valueOf(provider.toUpperCase()))

                // Store Google's unique user ID (the "sub" claim)
                // Example: "1234567890"
                .providerId(providerId)

                // All new users get COMPANY role (can be upgraded to ADMIN later)
                .role(Role.COMPANY)

                // SSO users are IMMEDIATELY ACTIVE (no email verification needed)
                // Google already verified their email, so we trust it
                .status(AccountStatus.ACTIVE)

                // Initialize failed login counter to 0
                .failedLoginAttempts(0)

                .build();
    }

    /**
     * Create OAuth2User with userId attribute
     *
     * WHAT THIS DOES:
     * Wraps the original OAuth2User and adds the userId to its attributes.
     * This allows the success handler to access the userId without querying the database again.
     *
     * WHY THIS IS NEEDED:
     * The user is saved in a @Transactional method, but the transaction may not commit
     * until after the method completes. If the success handler tries to query the user
     * immediately, it might not find them yet. By passing the userId directly in the
     * OAuth2User attributes, we avoid this timing issue.
     *
     * @param oauth2User Original OAuth2User from Google
     * @param userId Database user ID
     * @return New OAuth2User with userId attribute added
     */
    private OAuth2User createOAuth2UserWithUserId(OAuth2User oauth2User, String userId) {
        // Create a mutable copy of the attributes
        Map<String, Object> attributes = new HashMap<>(oauth2User.getAttributes());

        // Add our custom userId attribute
        attributes.put("userId", userId);

        // Create authorities (roles) for the user
        Set<GrantedAuthority> authorities = new HashSet<>(oauth2User.getAuthorities());

        // Return new OAuth2User with updated attributes
        return new DefaultOAuth2User(authorities, attributes, "email");
    }

    /**
     * Generate JWT Tokens for OAuth2 User
     *
     * WHEN THIS IS CALLED:
     * Called by OAuth2SuccessHandler after successful OAuth2 authentication.
     * This is the final step before redirecting user to frontend.
     *
     * WHAT THIS DOES:
     * 1. Fetch user from database by userId (passed from OAuth2User attributes)
     * 2. Generate JWT access token (15 minutes validity)
     * 3. Generate JWT refresh token (7 days validity)
     * 4. Return tokens to success handler
     *
     * TOKEN TYPE:
     * Uses standard JWT (NOT JWE) for OAuth2 login.
     * JWE encryption is only required for email/password login (Req 2.2.1).
     *
     * TOKEN CONTENTS:
     * Access Token JWT Claims:
     * - sub: User ID
     * - email: User's email
     * - role: User's role (COMPANY or ADMIN)
     * - iat: Issued at timestamp
     * - exp: Expiration timestamp (15 minutes)
     * - ip: Client IP address
     * - device: User agent string
     *
     * @param userId User's database ID (from OAuth2User attributes)
     * @param ipAddress Client's IP address (for audit logging)
     * @param deviceInfo User-Agent string (for audit logging)
     * @return TokenInternalDto containing access token, refresh token, and expiry times
     * @throws OAuth2AuthenticationException if user not found (shouldn't happen)
     */
    public TokenInternalDto generateTokensForOAuth2User(String userId, String ipAddress, String deviceInfo) {
        // STEP 1: Fetch user from database by ID
        // userId was passed through OAuth2User attributes to avoid transaction timing issues
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new OAuth2AuthenticationException("User not found after OAuth2 authentication"));

        // STEP 2: Generate JWT tokens (access + refresh)
        // TokenService creates signed JWT tokens with user claims
        return tokenService.generateTokens(
                user.getId(),           // Subject (sub claim)
                user.getEmail(),        // Email claim
                user.getRole().name(),  // Role claim (COMPANY or ADMIN)
                ipAddress,              // IP address (for audit)
                deviceInfo              // Device info (for audit)
        );
    }
}
