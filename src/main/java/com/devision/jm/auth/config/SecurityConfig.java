package com.devision.jm.auth.config;

import com.devision.jm.auth.filter.InternalApiKeyValidationFilter;
import com.devision.jm.auth.filter.JwtAuthenticationFilter;
import com.devision.jm.auth.service.impl.CustomOidcUserService;
import com.devision.jm.auth.service.impl.OAuth2AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Security Configuration - Spring Security Setup
 *
 * OVERVIEW:
 * This class configures Spring Security for both traditional JWT authentication
 * and Google OAuth2 SSO (Single Sign-On). It defines:
 * 1. Which endpoints are public vs protected
 * 2. How OAuth2 login flow works (automatic endpoint creation)
 * 3. Filter chain for JWT validation
 * 4. Stateless session management (no server-side sessions)
 *
 * AUTHENTICATION METHODS SUPPORTED:
 * - Email/Password Login: JWT with JWE encryption (Req 2.2.1)
 * - Google OAuth2 SSO: Standard JWT tokens (Req 2.3.1)
 * - Admin Login: Special admin credentials
 *
 * KEY SPRING SECURITY CONCEPTS:
 * - SecurityFilterChain: Defines security rules and filters
 * - oauth2Login(): Automatically creates OAuth2 endpoints (no controller needed!)
 * - Filters: Process requests before reaching controllers
 */
@Configuration          // Marks this as a Spring configuration class
@EnableWebSecurity      // Enables Spring Security's web security features
@EnableMethodSecurity   // Enables @PreAuthorize, @Secured annotations on methods
@RequiredArgsConstructor  // Lombok: generates constructor for final fields (dependency injection)
public class SecurityConfig {

    // Filter that validates JWT tokens from Authorization header (email/password login)
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    // Filter that validates X-Internal-API-Key header (requests from API Gateway)
    private final InternalApiKeyValidationFilter internalApiKeyValidationFilter;

    // Service that processes OAuth2 user data from Google (creates/links accounts)
    private final OAuth2AuthenticationService oauth2AuthenticationService;

    // Service that processes OIDC user data from Google (Google uses OIDC, not plain OAuth2)
    private final CustomOidcUserService customOidcUserService;

    // Handler that executes after successful OAuth2 login (generates tokens, redirects)
    private final OAuth2SuccessHandler oauth2SuccessHandler;
    private final OAuth2FailureHandler oauth2FailureHandler;

    // Cookie-based repository for storing OAuth2 authorization requests (stateless)
    private final HttpCookieOAuth2AuthorizationRequestRepository cookieAuthorizationRequestRepository;

    /**
     * Security Filter Chain - Main Security Configuration
     *
     * WHAT THIS METHOD DOES:
     * Defines the security rules for ALL incoming HTTP requests.
     * This is the CORE of Spring Security configuration.
     *
     * EXECUTION ORDER:
     * 1. Request arrives at Auth Service
     * 2. Filters process request (InternalApiKeyValidationFilter → JwtAuthenticationFilter)
     * 3. Authorization rules check if endpoint is public or requires authentication
     * 4. If OAuth2 endpoint, Spring Security handles OAuth2 flow automatically
     * 5. Request reaches controller (if authorized)
     *
     * @param http HttpSecurity object to configure security rules
     * @return SecurityFilterChain configured security filter chain
     * @throws Exception if configuration fails
     */
    @Bean  // Registers this as a Spring bean, auto-detected by Spring Security
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // ========== CORS Configuration ==========
                // Disable CORS at service level - Gateway handles CORS
                // API Gateway adds CORS headers, microservices don't need to
                .cors(AbstractHttpConfigurer::disable)

                // ========== CSRF Protection ==========
                // Disable CSRF for stateless API
                // CSRF tokens not needed because we use JWT tokens (not cookies)
                // Stateless = each request contains full auth info (JWT), no session
                .csrf(AbstractHttpConfigurer::disable)

                // ========== HTTP Headers Configuration ==========
                // Allow H2 console frames (development only)
                // Allows H2 database console to be embedded in iframe (same origin only)
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

                // ========== Session Management ==========
                // Stateless session management - NO server-side sessions
                // Why stateless? Microservices should be stateless for horizontal scaling
                // Each request contains JWT token, server doesn't store session data
                // Benefits: Multiple instances can handle any request, easier load balancing
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // ========== Authorization Rules ==========
                // Defines which endpoints require authentication and which are public
                .authorizeHttpRequests(auth -> auth
                        // PUBLIC ENDPOINTS - No authentication required (.permitAll())
                        .requestMatchers(
                                "/",  // Root endpoint (health check)

                                // Authentication endpoints
                                "/api/auth/register",         // User registration (Req 1.1.1)
                                "/api/auth/login",            // Email/password login (Req 2.2.1)
                                "/api/auth/refresh",          // Refresh access token (Req 2.2.2)
                                "/api/auth/activate/**",      // Email activation (Req 1.1.3)
                                "/api/auth/forgot-password",  // Request password reset
                                "/api/auth/reset-password/**",// Reset password with token
                                "/api/auth/validate",         // Validate JWT token (internal)
                                "/api/auth/countries",        // Get countries list
                                "/api/auth/admin/login",      // Admin login

                                // OAuth2 endpoints - AUTOMATICALLY CREATED by .oauth2Login() below
                                // These are Spring Security's built-in OAuth2 endpoints:
                                // - /oauth2/authorization/google -> Initiates Google login
                                // - /login/oauth2/code/google -> Google's callback endpoint
                                "/oauth2/**",         // Allows /oauth2/authorization/{provider}
                                "/login/oauth2/**",   // Allows /login/oauth2/code/{provider}

                                // Actuator endpoints (monitoring, health checks)
                                "/actuator/**"
                        ).permitAll()  // All above endpoints are PUBLIC (no JWT required)

                        // ADMIN ENDPOINTS - Require ADMIN role
                        // User must have JWT token with role="ROLE_ADMIN"
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // ALL OTHER ENDPOINTS - Require authentication
                        // User must have valid JWT token in Authorization header
                        .anyRequest().authenticated()
                )

                // ========== OAuth2 Login Configuration ==========
                // THIS IS WHERE THE MAGIC HAPPENS - Google SSO (Req 1.3.1, 2.3.1)
                //
                // .oauth2Login() AUTOMATICALLY creates these endpoints:
                // 1. /oauth2/authorization/google
                //    - Frontend redirects here to start Google login
                //    - Spring Security redirects to Google's login page
                //
                // 2. /login/oauth2/code/google
                //    - Google redirects here after successful login with authorization code
                //    - Spring Security automatically:
                //      a) Exchanges code for access token (calls Google's token endpoint)
                //      b) Fetches user info (calls Google's userinfo endpoint)
                //      c) Calls YOUR custom userService (oauth2AuthenticationService)
                //      d) Calls YOUR custom successHandler (oauth2SuccessHandler)
                //
                // YOU DON'T NEED TO CREATE A CONTROLLER FOR THESE ENDPOINTS!
                // Spring Security handles all OAuth2 protocol interactions automatically.
                .oauth2Login(oauth2 -> oauth2
                        // Cookie-based authorization request repository (for stateless sessions)
                        // Stores OAuth2 state in cookies instead of HTTP sessions
                        // Required because we use SessionCreationPolicy.STATELESS for JWT auth
                        // See: HttpCookieOAuth2AuthorizationRequestRepository
                        .authorizationEndpoint(authorization -> authorization
                                .authorizationRequestRepository(cookieAuthorizationRequestRepository))

                        // Custom user service to process OAuth2 user data
                        // After Spring Security fetches user info from Google, it calls this service
                        .userInfoEndpoint(userInfo -> userInfo
                                // YOUR CODE: Check if user exists, create/link account, auto-activate
                                // See: OAuth2AuthenticationService.loadUser()
                                .userService(oauth2AuthenticationService)
                                // OIDC User Service (Google uses OIDC, not plain OAuth2)
                                // This is required because Google returns an OIDC token
                                // See: CustomOidcUserService.loadUser()
                                .oidcUserService(customOidcUserService))

                        // Custom success handler to generate JWT tokens and redirect
                        // After authentication succeeds, this handler is called
                        // YOUR CODE: Generate access/refresh tokens, redirect to frontend with tokens
                        // See: OAuth2SuccessHandler.onAuthenticationSuccess()
                        .successHandler(oauth2SuccessHandler)

                        // Custom failure handler to handle OAuth2 authentication errors
                        // After authentication fails, this handler redirects to frontend with error
                        // See: OAuth2FailureHandler.onAuthenticationFailure()
                        .failureHandler(oauth2FailureHandler)
                )

                // ========== Filter Chain Configuration ==========
                // Filters process requests BEFORE they reach controllers
                // Execution order: InternalApiKeyValidationFilter → JwtAuthenticationFilter → Controllers

                // Add Internal API Key filter FIRST (validates X-Internal-API-Key header)
                // Validates requests coming from API Gateway to ensure they're legitimate
                // Position: Before SecurityContextHolderFilter (very early in filter chain)
                .addFilterBefore(internalApiKeyValidationFilter, SecurityContextHolderFilter.class)

                // Add JWT authentication filter SECOND (validates Authorization: Bearer <token>)
                // Extracts JWT from Authorization header, validates it, sets SecurityContext
                // Position: Before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        // Build and return the configured SecurityFilterChain
        return http.build();
    }

    /**
     * Password Encoder Bean
     *
     * WHAT THIS DOES:
     * Creates a BCrypt password encoder for hashing passwords.
     * BCrypt is a secure one-way hashing algorithm designed for passwords.
     *
     * HOW IT WORKS:
     * - When user registers: password → BCrypt hash → stored in database
     * - When user logs in: password → BCrypt hash → compared with stored hash
     * - Strength factor 12: 2^12 = 4096 hashing rounds (good security/performance balance)
     *
     * EXAMPLE:
     * Input:  "MyPassword123"
     * Output: "$2a$12$KIXWz8Y7nBZjVh0fK9xP3O7hX.3QZ5L8mN9R4bT6vU8sC2dE0fG1K"
     * (60 characters, includes salt, can never be reversed to original password)
     *
     * SECURITY:
     * - Each password gets a random salt (prevents rainbow table attacks)
     * - Computationally expensive (prevents brute force attacks)
     * - Industry standard for password storage
     *
     * @return BCryptPasswordEncoder with strength 12
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        // Strength 12 = 2^12 = 4096 iterations (higher = more secure but slower)
        // 12 is a good balance between security and performance for 2024
        return new BCryptPasswordEncoder(12);
    }

    /**
     * Authentication Manager Bean
     *
     * WHAT THIS DOES:
     * Creates the AuthenticationManager used by Spring Security to authenticate users.
     * This is the "brain" of Spring Security authentication.
     *
     * WHEN IT'S USED:
     * - Email/password login: Validates username/password against database
     * - Called by AuthService.login() method
     * - NOT used for OAuth2 login (OAuth2 has its own authentication flow)
     *
     * HOW IT WORKS:
     * 1. Receives UsernamePasswordAuthenticationToken with email/password
     * 2. Calls UserDetailsService (CustomUserDetailsService) to load user from database
     * 3. Uses PasswordEncoder to verify password hash matches
     * 4. Returns authenticated Authentication object if successful
     * 5. Throws BadCredentialsException if password doesn't match
     *
     * @param authConfig Spring's authentication configuration
     * @return AuthenticationManager authentication manager
     * @throws Exception if configuration fails
     */
    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        // Returns the default AuthenticationManager configured by Spring Security
        // This manager uses all registered AuthenticationProviders (DaoAuthenticationProvider by default)
        return authConfig.getAuthenticationManager();
    }
}
