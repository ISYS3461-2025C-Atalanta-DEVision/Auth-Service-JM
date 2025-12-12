package com.devision.jm.auth.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.io.*;
import java.time.Duration;
import java.util.Base64;

/**
 * OAuth2 Cookie Storage
 *
 * PURPOSE:
 * Stores OAuth2 state in cookies instead of sessions (we use stateless JWE).
 * what is stateless right?
 * Stateful (Session-based):
    Server stores: sessions["abc123"] = {userId: "123", email: "user@example.com"}
    Client sends: sessionId=abc123
    Server looks up: "Who is abc123?" → Finds user info
    Stateless (JWE):
    Token contains: {userId: "123", email: "user@example.com", role: "COMPANY"}
    Client sends: entire token
    Server decrypts token → All info is already there, no lookup needed!
 *
 * FLOW:
 * 1. User clicks "Sign in with Google"
 * 2. Store OAuth2 request → cookie
 * 3. Redirect to Google
 * 4. Google redirects back with code
 * 5. Read cookie → verify state → create user
 * 6. Delete cookie
 */
@Slf4j
@Component
public class HttpCookieOAuth2AuthorizationRequestRepository
        implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

    // Cookie name for storing OAuth2 authorization request
    public static final String OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME = "oauth2_auth_request";

    // Cookie expiration: 180 seconds (3 minutes) - enough time for OAuth2 flow
    private static final int COOKIE_EXPIRE_SECONDS = 180;

    /**
     * Load OAuth2 request from cookie (called during Google callback)
     */
    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        OAuth2AuthorizationRequest authRequest = getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(this::deserialize)
                .orElse(null);
        log.debug("Loading OAuth2 authorization request from cookie: {}", authRequest != null ? "Found" : "Not found");
        return authRequest;
    }

    /**
     * Save OAuth2 request to cookie (called when user clicks "Sign in with Google")
     */
    @Override
    public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest,
                                          HttpServletRequest request,
                                          HttpServletResponse response) {
        if (authorizationRequest == null) {
            removeAuthorizationRequestCookies(request, response);
            return;
        }

        // Serialize authorization request and store in cookie
        String cookieValue = serialize(authorizationRequest);
        log.debug("Saving OAuth2 authorization request to cookie");
        addCookie(response, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, cookieValue, COOKIE_EXPIRE_SECONDS);
    }

    /**
     * Remove OAuth2 request cookie (cleanup after callback processed)
     */
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
                                                                  HttpServletResponse response) {
        OAuth2AuthorizationRequest authorizationRequest = loadAuthorizationRequest(request);
        if (authorizationRequest != null) {
            log.debug("Removing OAuth2 authorization request cookie");
            removeAuthorizationRequestCookies(request, response);
        }
        return authorizationRequest;
    }

    // Helper: Get cookie by name
    private java.util.Optional<Cookie> getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return java.util.Optional.of(cookie);
                }
            }
        }
        return java.util.Optional.empty();
    }

    // Helper: Add cookie to response
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        // SameSite=None required for cross-domain OAuth2 (API Gateway → Auth Service)
        ResponseCookie cookie = ResponseCookie.from(name, value)
                .path("/auth-service/")  // Match API Gateway routing
                .httpOnly(true)           // Prevent JavaScript access
                .secure(true)             // HTTPS only
                .sameSite("None")         // Allow cross-site requests
                .maxAge(Duration.ofSeconds(maxAge))
                .build();

        // Add Set-Cookie header to response
        log.debug("Setting OAuth2 cookie: {}", cookie.toString());
        response.addHeader("Set-Cookie", cookie.toString());
    }

    // Helper: Delete OAuth2 cookies
    private void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .ifPresent(cookie -> {
                    ResponseCookie deleteCookie = ResponseCookie.from(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, "")
                            .path("/auth-service/")
                            .httpOnly(true)
                            .secure(true)
                            .sameSite("None")
                            .maxAge(0)  // Delete cookie
                            .build();

                    response.addHeader("Set-Cookie", deleteCookie.toString());
                });
    }

    // Helper: Serialize request to Base64
    private String serialize(OAuth2AuthorizationRequest authorizationRequest) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(authorizationRequest);
            return Base64.getUrlEncoder().encodeToString(baos.toByteArray());
        } catch (IOException e) {
            log.error("Failed to serialize OAuth2AuthorizationRequest", e);
            throw new IllegalArgumentException("Failed to serialize OAuth2AuthorizationRequest", e);
        }
    }

    // Helper: Deserialize Base64 to request
    private OAuth2AuthorizationRequest deserialize(Cookie cookie) {
        try (ByteArrayInputStream bais = new ByteArrayInputStream(
                Base64.getUrlDecoder().decode(cookie.getValue()));
             ObjectInputStream ois = new ObjectInputStream(bais)) {
            return (OAuth2AuthorizationRequest) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            log.error("Failed to deserialize OAuth2AuthorizationRequest", e);
            throw new IllegalArgumentException("Failed to deserialize OAuth2AuthorizationRequest", e);
        }
    }
}
