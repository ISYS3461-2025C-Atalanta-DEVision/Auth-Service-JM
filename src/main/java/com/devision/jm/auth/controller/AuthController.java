package com.devision.jm.auth.controller;

import com.devision.jm.auth.api.external.dto.*;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.util.CountryValidator;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Authentication and authorization endpoints")
public class AuthController {

    private final AuthenticationApi authenticationService;

    @PostMapping("/register")
    @Operation(summary = "Register a new company", description = "Register a new company account (1.1.1 - 1.2.4)")
    public ResponseEntity<ApiResponse<CompanyProfileResponse>> register(
            @Valid @RequestBody CompanyRegistrationRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        ApiResponse<CompanyProfileResponse> response = authenticationService.registerCompany(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @PostMapping("/login")
    @Operation(summary = "Login", description = "Authenticate company user (2.1.1 - 2.2.2)")
    public ResponseEntity<ApiResponse<LoginResponse>> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Login request received for email: {} from IP: {}", request.getEmail(), ipAddress);
        ApiResponse<LoginResponse> response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh token", description = "Refresh access token using refresh token (2.3.3)")
    public ResponseEntity<ApiResponse<LoginResponse>> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        log.debug("Token refresh request received");
        ApiResponse<LoginResponse> response = authenticationService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(summary = "Logout", description = "Logout and invalidate tokens (2.2.3)")
    public ResponseEntity<ApiResponse<Void>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        ApiResponse<Void> response = authenticationService.logout(accessToken, refreshToken);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/activate/{token}")
    @Operation(summary = "Activate account", description = "Activate account using email token (1.1.3)")
    public ResponseEntity<ApiResponse<Void>> activateAccount(@PathVariable String token) {
        log.info("Account activation request received");
        ApiResponse<Void> response = authenticationService.activateAccount(token);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset", description = "Request a password reset email")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@RequestParam String email) {
        log.info("Password reset request for email: {}", email);
        ApiResponse<Void> response = authenticationService.requestPasswordReset(email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/reset-password/{token}")
    @Operation(summary = "Reset password", description = "Reset password using reset token")
    public ResponseEntity<ApiResponse<Void>> resetPassword(
            @PathVariable String token,
            @RequestParam String newPassword) {
        log.info("Password reset attempt with token");
        ApiResponse<Void> response = authenticationService.resetPassword(token, newPassword);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/change-password")
    @Operation(summary = "Change password", description = "Change password for authenticated user")
    public ResponseEntity<ApiResponse<Void>> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @RequestAttribute("userId") String userId) {
        log.info("Password change request for user: {}", userId);
        ApiResponse<Void> response = authenticationService.changePassword(userId, request);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/validate")
    @Operation(summary = "Validate token", description = "Validate access token (used by API Gateway)")
    public ResponseEntity<Boolean> validateToken(
            @RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.ok(false);
        }
        String token = authHeader.substring(7);
        boolean isValid = authenticationService.validateToken(token);
        return ResponseEntity.ok(isValid);
    }

    @GetMapping("/countries")
    @Operation(summary = "Get valid countries", description = "Get list of valid countries for registration dropdown (1.24)")
    public ResponseEntity<ApiResponse<Set<String>>> getCountries() {
        Set<String> countries = CountryValidator.getValidCountries();
        return ResponseEntity.ok(ApiResponse.success(countries));
    }

    // ==================== Admin Login ====================

    @PostMapping("/admin/login")
    @Operation(summary = "Admin login", description = "Authenticate admin user (6.1.1)")
    public ResponseEntity<ApiResponse<LoginResponse>> adminLogin(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Admin login request received from IP: {}", ipAddress);
        // Note: The AuthenticationService will verify the ADMIN role
        ApiResponse<LoginResponse> response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // ==================== Helper Methods ====================

    private String getClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
