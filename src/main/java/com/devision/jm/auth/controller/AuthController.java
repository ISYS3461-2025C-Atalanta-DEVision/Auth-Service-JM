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
@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationApi authenticationService;

    // ==================== REGISTRATION ====================
    @PostMapping("/register")
    public ResponseEntity<CompanyProfileResponse> register(
            @Valid @RequestBody CompanyRegistrationRequest request) {
        log.info("Registration request received for email: {}", request.getEmail());
        CompanyProfileResponse response = authenticationService.registerCompany(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // ==================== LOGIN ====================
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Login request received for email: {} from IP: {}", request.getEmail(), ipAddress);
        LoginResponse response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // ==================== TOKEN REFRESH ====================
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest request) {
        log.debug("Token refresh request received");
        LoginResponse response = authenticationService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    // ==================== LOGOUT ====================
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @RequestBody(required = false) RefreshTokenRequest refreshTokenRequest) {

        String accessToken = null;
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            accessToken = authHeader.substring(7);
        }

        String refreshToken = refreshTokenRequest != null ? refreshTokenRequest.getRefreshToken() : null;

        authenticationService.logout(accessToken, refreshToken);
        return ResponseEntity.ok().build();
    }

    // ==================== ACCOUNT ACTIVATION ====================
    @GetMapping("/activate/{token}")
    public ResponseEntity<Void> activateAccount(@PathVariable String token) {
        log.info("Account activation request received");
        authenticationService.activateAccount(token);
        return ResponseEntity.ok().build();
    }

    // ==================== FORGOT PASSWORD ====================
    @PostMapping("/forgot-password")
    public ResponseEntity<Void> forgotPassword(@RequestParam String email) {
        log.info("Password reset request for email: {}", email);
        authenticationService.requestPasswordReset(email);
        return ResponseEntity.ok().build();
    }

    // ==================== RESET PASSWORD ====================
    @PostMapping("/reset-password/{token}")
    public ResponseEntity<Void> resetPassword(
            @PathVariable String token,
            @RequestParam String newPassword) {
        log.info("Password reset attempt with token");
        authenticationService.resetPassword(token, newPassword);
        return ResponseEntity.ok().build();
    }

    // ==================== CHANGE PASSWORD ====================
    @PostMapping("/change-password")
    public ResponseEntity<Void> changePassword(
            @Valid @RequestBody PasswordChangeRequest request,
            @RequestAttribute("userId") String userId) {
        log.info("Password change request for user: {}", userId);
        authenticationService.changePassword(userId, request);
        return ResponseEntity.ok().build();
    }

    // ==================== TOKEN VALIDATION ====================
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
    @GetMapping("/countries")
    public ResponseEntity<Set<String>> getCountries() {
        Set<String> countries = CountryValidator.getValidCountries();
        return ResponseEntity.ok(countries);
    }

    // ==================== ADMIN LOGIN ====================
    @PostMapping("/admin/login")
    public ResponseEntity<LoginResponse> adminLogin(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        String ipAddress = getClientIp(httpRequest);
        log.info("Admin login request received from IP: {}", ipAddress);
        LoginResponse response = authenticationService.login(request, ipAddress);
        return ResponseEntity.ok(response);
    }

    // ==================== HELPER METHODS ====================
    private String getClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader("X-Forwarded-For");
        if (forwardedFor != null && !forwardedFor.isEmpty()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
