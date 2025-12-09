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
 * Note: Controller communicates with Business Logic Layer (AuthenticationApi)
 * and does NOT directly access Repository Layer (A.2.2).
 */
@Slf4j                          // Creates a 'log' object for logging (log.info, log.debug, etc.)
@RestController                 // Marks this class as a REST controller (returns JSON by default)
@RequestMapping("/api/auth")    // Base URL path - all endpoints start with /api/auth
@RequiredArgsConstructor        // Lombok generates constructor for 'final' fields (dependency injection)
public class AuthController {

    // Injected via constructor - this is the business logic layer
    private final AuthenticationApi authenticationService;

    // ==================== REGISTRATION ====================
    // POST /api/auth/register
    // Registers a new company account. Returns 201 CREATED on success.
    // @Valid triggers validation on request fields (e.g., @NotNull, @Email)
    // @RequestBody parses JSON body into CompanyRegistrationRequest object
    @PostMapping("/register")
    // ResponseEntity<T> = HTTP response wrapper that lets us set status code, headers, and body
    // ApiResponse<T> = Our custom wrapper with success/error info + data payload
    // CompanyProfileResponse = The actual data (company details after registration)
    public ResponseEntity<ApiResponse<CompanyProfileResponse>> register(
            // @Valid = Run validation rules defined in CompanyRegistrationRequest (e.g., @NotNull, @Email)
            //          If validation fails, Spring auto-returns 400 Bad Request
            // @RequestBody = Parse incoming JSON into CompanyRegistrationRequest object
            @Valid @RequestBody CompanyRegistrationRequest request) {
        // Log the registration attempt (email only, not password for security)
        log.info("Registration request received for email: {}", request.getEmail());
        // Delegate to service layer - controller doesn't contain business logic
        ApiResponse<CompanyProfileResponse> response = authenticationService.registerCompany(request);
        // Return HTTP 201 Created (not 200 OK) because we created a new resource
        // .body(response) sets the JSON response body
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ==================== LOGIN ====================
    // POST /api/auth/login
    // Authenticates user and returns JWT tokens (access + refresh).
    // Extracts client IP for security logging/audit.
    @PostMapping("/login")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Login request received for email: {} from IP: {}", request.getEmail(), ipAddress);
        ApiResponse<LoginResponse> response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // ==================== TOKEN REFRESH ====================
    // POST /api/auth/refresh
    // Gets new access token using valid refresh token.
    // Called when access token expires but refresh token is still valid.
    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        log.debug("Token refresh request received");
        ApiResponse<LoginResponse> response = authenticationService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    // ==================== LOGOUT ====================
    // POST /api/auth/logout
    // Invalidates tokens (adds to blacklist in Redis).
    // Both tokens are optional - invalidates whichever are provided.
    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        // Extract access token from "Bearer <token>" header
        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);  // Remove "Bearer " prefix (7 chars)
        }

        // Extract refresh token from body if provided
        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        ApiResponse<Void> response = authenticationService.logout(accessToken, refreshToken);
        return ResponseEntity.ok(response);
    }

    // ==================== ACCOUNT ACTIVATION ====================
    // GET /api/auth/activate/{token}
    // Activates account using token sent via email after registration.
    // @PathVariable extracts {token} from the URL path.
    @GetMapping("/activate/{token}")
    public ResponseEntity<ApiResponse<Void>> activateAccount(@PathVariable String token) {
        log.info("Account activation request received");
        ApiResponse<Void> response = authenticationService.activateAccount(token);
        return ResponseEntity.ok(response);
    }

    // ==================== FORGOT PASSWORD ====================
    // POST /api/auth/forgot-password?email=user@example.com
    // Sends password reset email. Always returns success to prevent email enumeration.
    // @RequestParam extracts 'email' from query string.
    @PostMapping("/forgot-password")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestParam String email) {
        log.info("Password reset request for email: {}", email);
        ApiResponse<Void> response = authenticationService.requestPasswordReset(email);
        return ResponseEntity.ok(response);
    }

    // ==================== RESET PASSWORD ====================
    // POST /api/auth/reset-password/{token}?newPassword=xxx
    // Resets password using token from reset email.
    @PostMapping("/reset-password/{token}")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @PathVariable String token,
            @RequestParam String newPassword) {
        log.info("Password reset attempt with token");
        ApiResponse<Void> response = authenticationService.resetPassword(token, newPassword);
        return ResponseEntity.ok(response);
    }

    // ==================== CHANGE PASSWORD ====================
    // POST /api/auth/change-password
    // Changes password for authenticated user (requires current password).
    // @RequestAttribute reads userId set by gateway from JWT token.
    @PostMapping("/change-password")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @RequestAttribute("userId") String userId) {
        log.info("Password change request for user: {}", userId);
        ApiResponse<Void> response = authenticationService.changePassword(userId, request);
        return ResponseEntity.ok(response);
    }

    // ==================== TOKEN VALIDATION ====================
    // GET /api/auth/validate
    // Validates if access token is still valid. Used by API Gateway.
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.ok(false);
        }
        String token = authHeader.substring(7);
        boolean isValid = authenticationService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }

    // ==================== COUNTRIES LIST ====================
    // GET /api/auth/countries
    // Returns valid countries for registration dropdown.
    @GetMapping("/countries")
    public ResponseEntity<ApiResponse<Set<String>>> getCountries() {
        Set<String> countries = CountryValidator.getValidCountries();
        return ResponseEntity.ok(ApiResponse.success(countries));
    }

    // ==================== ADMIN LOGIN ====================
    // POST /api/auth/admin/login
    // Same as regular login but service layer verifies ADMIN role.
    @PostMapping("/admin/login")
    public ResponseEntity<ApiResponse<LoginResponse>> adminLogin(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Admin login request received from IP: {}", ipAddress);
        ApiResponse<LoginResponse> response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // ==================== HELPER METHODS ====================

    // Extracts client's real IP address.
    // Checks X-Forwarded-For header first (set by proxies/load balancers),
    // falls back to direct remote address if not present.
    private String getClientIp(HttpServletRequest request) {
        // X-Forwarded-For format: "client, proxy1, proxy2" - get first (original client)
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
