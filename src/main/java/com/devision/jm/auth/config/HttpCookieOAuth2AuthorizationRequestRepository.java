package com.devision.jm.auth.config;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Component;

import java.io.*;
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
        return getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .map(this::deserialize)
                .orElse(null);
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
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(true);  // Prevents JavaScript access (XSS protection)
        cookie.setMaxAge(maxAge);
        // Note: Secure flag (HTTPS only) is handled by Render's reverse proxy
        response.addCookie(cookie);
    }

    /**
     * Remove Authorization Request Cookies
     */
    private void removeAuthorizationRequestCookies(HttpServletRequest request, HttpServletResponse response) {
        getCookie(request, OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME)
                .ifPresent(cookie -> {
                    Cookie deleteCookie = new Cookie(OAUTH2_AUTHORIZATION_REQUEST_COOKIE_NAME, "");
                    deleteCookie.setPath("/");
                    deleteCookie.setHttpOnly(true);
                    deleteCookie.setMaxAge(0);  // Expire immediately
                    response.addCookie(deleteCookie);
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
            throw new IllegalArgumentException("Failed to deserialize OAuth2AuthorizationRequest", e);
        }
    }
}
