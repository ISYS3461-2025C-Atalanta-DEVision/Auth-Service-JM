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
 * Cookie-Based OAuth2 Authorization Request Repository
 *
 * WHY THIS IS NEEDED:
 * Spring Security's default OAuth2 implementation uses HTTP sessions to store
 * the authorization request state between:
 * 1. Initial request to /oauth2/authorization/google
 * 2. Callback from Google to /login/oauth2/code/google
 *
 * PROBLEM:
 * Our Auth Service uses stateless session management (SessionCreationPolicy.STATELESS)
 * for JWT-based authentication. This means no HTTP sessions are created, so the
 * default session-based OAuth2 state storage doesn't work.
 *
 * SOLUTION:
 * This repository stores OAuth2 authorization request in cookies instead of sessions.
 * Cookies are sent back and forth with each request, allowing stateless OAuth2 flow.
 *
 * HOW IT WORKS:
 * 1. User clicks "Sign in with Google" → /oauth2/authorization/google
 * 2. Spring Security creates OAuth2AuthorizationRequest with state parameter
 * 3. THIS REPOSITORY serializes request → Base64 → stores in cookie
 * 4. Browser redirects to Google with state parameter
 * 5. Google authenticates user → redirects to /login/oauth2/code/google with state
 * 6. THIS REPOSITORY reads cookie → deserializes → retrieves authorization request
 * 7. Spring Security validates state matches → processes callback
 *
 * SECURITY:
 * - Uses HttpOnly cookies (JavaScript can't access)
 * - Short expiration (180 seconds = 3 minutes)
 * - State parameter prevents CSRF attacks
 * - Cookies are cleared after use
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
     * Load Authorization Request from Cookie
     *
     * Called by Spring Security when processing OAuth2 callback.
     * Retrieves the authorization request that was stored when user initiated login.
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
     * Save Authorization Request to Cookie
     *
     * Called by Spring Security when user initiates OAuth2 login.
     * Stores the authorization request in a cookie so it can be retrieved during callback.
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
     * Remove Authorization Request (after processing callback)
     *
     * Called by Spring Security after OAuth2 callback is processed.
     * Returns the stored request and deletes the cookie.
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

    /**
     * Get Cookie by Name
     */
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

    /**
     * Add Cookie to Response
     */
    private void addCookie(HttpServletResponse response, String name, String value, int maxAge) {
        // Use ResponseCookie to set SameSite attribute
        // CRITICAL: SameSite=None is required for cross-site OAuth2 requests
        // When browser makes OAuth2 request through API Gateway (api-gateway-khhr.onrender.com)
        // and callback comes back, the cookie must be sent even though it's a cross-site request
        ResponseCookie cookie = ResponseCookie.from(name, value)
                // Set path to /auth-service/ to work with API Gateway routing
                // Cookie is scoped to /auth-service/ path so it's sent on both:
                // 1. Initial request: /auth-service/oauth2/authorization/google
                // 2. Callback request: /auth-service/login/oauth2/code/google
                .path("/auth-service/")
                // HttpOnly prevents JavaScript access (XSS protection)
                .httpOnly(true)
                // Secure ensures cookie is only sent over HTTPS
                .secure(true)
                // SameSite=None allows cookie to be sent in cross-site requests
                // Required for OAuth2 flow through API Gateway
                // Must be combined with Secure=true (browser requirement)
                .sameSite("None")
                // Cookie expiration
                .maxAge(Duration.ofSeconds(maxAge))
                .build();

        // Add Set-Cookie header to response
        response.addHeader("Set-Cookie", cookie.toString());
    }

    /**
     * Remove Authorization Request Cookies
     */
    private void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .ifPresent(cookie -> {
                    // Create cookie with maxAge=0 to delete it
                    ResponseCookie deleteCookie = ResponseCookie.from(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, "")
                            .path("/auth-service/")  // Must match the path set in addCookie
                            .httpOnly(true)
                            .secure(true)
                            .sameSite("None")  // Must match original cookie
                            .maxAge(0)  // Expire immediately
                            .build();

                    response.addHeader("Set-Cookie", deleteCookie.toString());
                });
    }

    /**
     * Serialize OAuth2AuthorizationRequest to Base64 String
     */
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

    /**
     * Deserialize Base64 String to OAuth2AuthorizationRequest
     */
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
