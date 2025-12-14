package com.devision.jm.auth.controller;

import com.devision.jm.auth.api.external.dto.*;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.util.CountryValidator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Set;

/**
 * Authentication Controller
 *
 * REST controller for authentication endpoints.
 * Implements the Presentation Layer (A.1.1, A.2.2).
 *
 * Microservice Architecture (A.3.1):
 * - Auth Service handles: registration, login, logout, tokens
 * - Profile Service handles: user profile (via Kafka)
 *
 * Note: Controller communicates with Business Logic Layer (AuthenticationApi)
 * and does NOT directly access Repository Layer (A.2.2).
 */
@Slf4j  // Lombok: auto-generates logger field 'log' for logging
@RestController  // Marks as REST controller - returns JSON data directly (not views)
@RequestMapping("/api/auth")  // Base URL path for all endpoints in this controller
@RequiredArgsConstructor  // Lombok: generates constructor for final fields (dependency injection)
public class AuthController {

    // Business logic layer - injected by Spring via constructor
    private final AuthenticationApi authenticationService;

    // ==================== REGISTRATION ====================
    // POST /api/auth/register - Register a new company account
    @PostMapping("/register")
    public ResponseEntity<RegistrationResponse> register(
            @Valid @RequestBody CompanyRegistrationRequest request) {
        // @Valid - triggers Bean Validation (checks @Email, @Size, @Pattern on DTO)
        // @RequestBody - deserializes JSON request body to CompanyRegistrationRequest object
        log.info("Registration request received for email: {}", request.getEmail());
        RegistrationResponse response = authenticationService.registerCompany(request);
        // Return HTTP 201 Created with the registration response
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ==================== LOGIN ====================
    // POST /api/auth/login - Authenticate user and return JWE tokens
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {  // Injected by Spring to access HTTP details
        // Extract client IP for brute-force protection and audit logging
        String ipAddress = getClientIp(httpRequest);
        log.info("Login request received for email: {} from IP: {}", request.getEmail(), ipAddress);
        // Authenticate user and generate tokens
        LoginResponse response = authenticationService.login(request, ipAddress);
        // Return HTTP 200 OK with access token, refresh token, and user info
        return ResponseEntity.ok(response);
    }

    // ==================== TOKEN REFRESH ====================
    // POST /api/auth/refresh - Exchange refresh token for new access + refresh tokens
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        // debug level - less verbose since refresh is routine operation
        log.debug("Token refresh request received");
        // Validate refresh token and generate new token pair
        LoginResponse response = authenticationService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    // ==================== LOGOUT ====================
    // POST /api/auth/logout - Revoke tokens (add to Redis blacklist)
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            // Authorization header is optional - may contain access token
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            // Request body is optional - may contain refresh token
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        // Extract access token from "Authorization: Bearer <token>" header
        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);  // Remove "Bearer " prefix (7 characters)
        }

        // Safely extract refresh token from request body if present
        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        // Revoke both tokens (adds to Redis blacklist for invalidation)
        authenticationService.logout(accessToken, refreshToken);
        // Return HTTP 200 OK with empty body
        return ResponseEntity.ok().build();
    }

    // ==================== ACCOUNT ACTIVATION ====================
    // GET /api/auth/activate/{token} - Activate account via email link (Requirement 1.1.3)
    @GetMapping("/activate/{token}")
    public ResponseEntity<Void> activateAccount(
            @PathVariable String token) {  // Extract {token} from URL path
        log.info("Account activation request received");
        // Validate token and change account status from PENDING_ACTIVATION to ACTIVE
        authenticationService.activateAccount(token);
        return ResponseEntity.ok().build();
    }

    // ==================== TOKEN VALIDATION ====================
    // GET /api/auth/validate - Validate JWE token (used by API Gateway)
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        // Check if Authorization header is present and has Bearer token format
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.ok(false);  // Invalid format = not valid
        }
        // Extract token and validate
        String token = authHeader.substring(7);  // Remove "Bearer " prefix
        boolean isValid = authenticationService.validateToken(token);
        // Return true if token is valid, false otherwise
        return ResponseEntity.ok(isValid);
    }

    // ==================== COUNTRIES LIST ====================
    // GET /api/auth/countries - Get list of valid countries for registration (Requirement 1.24)
    @GetMapping("/countries")
    public ResponseEntity<Set<String>> getCountries() {
        // Return predefined list of valid countries for registration dropdown
        Set<String> countries = CountryValidator.getValidCountries();
        return ResponseEntity.ok(countries);
    }

    // ==================== ADMIN LOGIN ====================
    // POST /api/auth/admin/login - Admin authentication endpoint
    @PostMapping("/admin/login")
    public ResponseEntity<LoginResponse> adminLogin(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Admin login request received from IP: {}", ipAddress);
        // Currently uses same logic as regular login
        // Can be extended for admin-specific validation if needed
        LoginResponse response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // NOTE: /api/auth/profile endpoint removed - profile is now handled by Profile Service

    // ==================== HELPER METHODS ====================
    /**
     * Extract real client IP address from request.
     * Handles proxy/load balancer scenarios (Render, Cloudflare, etc.)
     *
     * @param request HTTP request object
     * @return Client IP address
     */
    private String getClientIp(HttpServletRequest request) {
        // X-Forwarded-For header is set by proxies/load balancers
        // Contains original client IP (may have multiple IPs if multiple proxies)
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            // Take first IP (original client) if multiple proxies added IPs
            return forwardedFor.split(",")[0].trim();
        }
        // Fallback for direct connections (local development)
        return request.getRemoteAddr();
    }
}
