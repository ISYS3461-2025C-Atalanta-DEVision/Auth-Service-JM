package com.devision.jm.auth.config;

import com.devision.jm.auth.api.internal.dto.TokenInternalDto;
import com.devision.jm.auth.service.impl.OAuth2AuthenticationService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * OAuth2 Authentication Success Handler - Post-OAuth2 Processing
 *
 * WHAT THIS DOES:
 * This handler is called AFTER Google OAuth2 authentication succeeds.
 * It's the final step in the OAuth2 flow before returning to the frontend.
 *
 * WHEN IT'S CALLED:
 * Automatically invoked by Spring Security after:
 * 1. User successfully logs in with Google
 * 2. Spring Security exchanges authorization code for access token
 * 3. Spring Security fetches user info from Google
 * 4. OAuth2AuthenticationService creates/links user account
 * 5. → THIS HANDLER EXECUTES (final step)
 *
 * WHAT IT DOES:
 * 1. Extracts user email from OAuth2User object
 * 2. Generates JWT access token and refresh token
 * 3. Publishes LOGIN_SUCCESS event to Kafka
 * 4. Redirects browser to frontend with tokens in URL parameters
 *
 * FLOW POSITION:
 * Google Login → Google Callback → Token Exchange → Fetch User Info
 * → OAuth2AuthenticationService → THIS HANDLER → Frontend Redirect
 *
 * TOKEN TYPE:
 * Uses standard JWT (NOT JWE) for OAuth2 login (Req 2.3.1)
 * JWE is only required for email/password login (Req 2.2.1)
 *
 * CONFIGURATION:
 * Registered in SecurityConfig.java:
 * .oauth2Login(oauth2 -> oauth2.successHandler(oauth2SuccessHandler))
 */
@Slf4j              // Lombok: auto-generates logger
@Component          // Spring: registers this as a bean
@RequiredArgsConstructor  // Lombok: generates constructor for final fields
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    // Service that generates JWT tokens and publishes events
    private final OAuth2AuthenticationService oauth2AuthenticationService;

    // Jackson ObjectMapper for converting objects to JSON (used in API response)
    private final ObjectMapper objectMapper;

    // Frontend URL where user will be redirected with tokens
    // Example: https://job-manager-frontend.com
    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    /**
     * Main OAuth2 Success Handler Method
     *
     * WHEN THIS IS CALLED:
     * Automatically invoked by Spring Security after successful OAuth2 authentication.
     * This is triggered after:
     * - Google redirected to /login/oauth2/code/google
     * - Spring Security exchanged code for access token
     * - Spring Security fetched user info from Google
     * - OAuth2AuthenticationService.loadUser() completed (user created/linked)
     *
     * EXECUTION FLOW:
     * 1. Extract user email from OAuth2User object (from Google)
     * 2. Get client's IP address and device info for logging
     * 3. Generate JWT access token and refresh token
     * 4. Publish LOGIN_SUCCESS event to Kafka (for audit trail)
     * 5. Redirect browser to frontend with tokens OR return JSON response
     *
     * REDIRECT FORMATS:
     * - Browser: https://frontend.com/oauth2/callback?access_token=xxx&refresh_token=yyy&expires_in=900
     * - API: JSON response with tokens
     *
     * @param request HTTP request from Google callback
     * @param response HTTP response to send back
     * @param authentication Authentication object containing OAuth2User data
     * @throws IOException if redirect/response fails
     * @throws ServletException if servlet error occurs
     */
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

        // STEP 1: Extract OAuth2 user data
        // The Authentication object contains OAuth2User with Google's user info
        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();

        // Extract email and userId from OAuth2User attributes
        // Google returns: { "sub": "12345", "email": "user@gmail.com", "name": "John Doe", ... }
        // We added userId in OAuth2AuthenticationService.createOAuth2UserWithUserId()
        String email = oauth2User.getAttribute("email");
        String userId = oauth2User.getAttribute("userId");

        log.info("OAuth2 authentication successful for: {} (userId: {})", email, userId);

        try {
            // STEP 2: Get client information for audit logging
            // Extract IP address from request (handles proxy/load balancer scenarios)
            String ipAddress = getClientIp(request);

            // Extract browser/device info from User-Agent header
            // Example: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
            String deviceInfo = request.getHeader("User-Agent");

            // STEP 3: Generate JWT tokens (NOT JWE for OAuth2)
            // This method:
            // - Fetches user by ID (no database transaction timing issues)
            // - Generates access token (15 minutes validity)
            // - Generates refresh token (7 days validity)
            // - Returns TokenInternalDto with both tokens and expiry times
            TokenInternalDto tokens = oauth2AuthenticationService.generateTokensForOAuth2User(
                    userId, ipAddress, deviceInfo);

            // STEP 4: Send response based on client type
            // Check if client wants JSON response (API client) or browser redirect
            if (isApiRequest(request)) {
                // API CLIENT: Return JSON response with tokens
                // Used for mobile apps or SPA that initiate OAuth2 programmatically
                sendJsonResponse(response, tokens);
            } else {
                // BROWSER CLIENT: Redirect to frontend with tokens in URL
                // Used for standard browser-based OAuth2 flow (most common)
                redirectToFrontend(request, response, tokens);
            }

        } catch (Exception e) {
            // If anything fails, log error and return 500 error to client
            log.error("Failed to process OAuth2 success for email: {}", email, e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to process authentication");
        }
    }

    /**
     * Send JSON Response for API Clients
     *
     * WHEN THIS IS USED:
     * When the client sends "Accept: application/json" header.
     * Used for mobile apps or SPAs that initiate OAuth2 programmatically.
     *
     * RESPONSE FORMAT:
     * {
     *   "success": true,
     *   "message": "OAuth2 authentication successful",
     *   "data": {
     *     "accessToken": "eyJhbGciOiJIUzUxMiJ9...",
     *     "refreshToken": "eyJhbGciOiJIUzUxMiJ9...",
     *     "tokenType": "Bearer",
     *     "expiresIn": 900,        // Access token expires in 15 minutes
     *     "refreshExpiresIn": 604800  // Refresh token expires in 7 days
     *   }
     * }
     *
     * @param response HTTP response to write JSON to
     * @param tokens TokenInternalDto containing access and refresh tokens
     * @throws IOException if writing to response fails
     */
    private void sendJsonResponse(HttpServletResponse response, TokenInternalDto tokens) throws IOException {
        // Set response content type to JSON
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        // Build JSON response body
        // Using Map.of() to create immutable map (Java 9+ feature)
        Map<String, Object> responseBody = Map.of(
                "success", true,
                "message", "OAuth2 authentication successful",
                "data", Map.of(
                        "accessToken", tokens.getAccessToken(),    // JWT access token
                        "refreshToken", tokens.getRefreshToken(),  // JWT refresh token
                        "tokenType", "Bearer",                     // Standard bearer token type
                        // Calculate seconds until access token expires
                        "expiresIn", Duration.between(LocalDateTime.now(),
                                tokens.getAccessTokenExpiry()).getSeconds(),
                        // Calculate seconds until refresh token expires
                        "refreshExpiresIn", Duration.between(LocalDateTime.now(),
                                tokens.getRefreshTokenExpiry()).getSeconds()
                )
        );

        // Convert map to JSON string and write to response
        // ObjectMapper.writeValueAsString() converts Java object → JSON
        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
    }

    /**
     * Redirect to Frontend with Tokens in URL
     *
     * WHEN THIS IS USED:
     * When the client is a browser (standard OAuth2 flow).
     * This is the MOST COMMON flow for web applications.
     *
     * HOW IT WORKS:
     * 1. Build redirect URL with frontend callback route
     * 2. Add tokens as query parameters
     * 3. Send HTTP 302 redirect response
     * 4. Browser automatically follows redirect to frontend
     * 5. Frontend JavaScript extracts tokens from URL
     *
     * REDIRECT URL FORMAT:
     * https://job-manager-frontend.com/oauth2/callback?
     *   access_token=eyJhbGciOiJIUzUxMiJ9...
     *   &refresh_token=eyJhbGciOiJIUzUxMiJ9...
     *   &expires_in=900
     *
     * FRONTEND HANDLING:
     * Frontend should:
     * 1. Extract tokens from URL query parameters
     * 2. Store them in localStorage or secure storage
     * 3. Clear tokens from URL (for security)
     * 4. Redirect to dashboard
     *
     * SECURITY NOTE:
     * Tokens in URL are visible in browser history. For production:
     * - Use HTTPS to encrypt transmission
     * - Frontend should immediately remove tokens from URL
     * - Consider using state parameter for CSRF protection
     *
     * @param request HTTP request (needed for redirect strategy)
     * @param response HTTP response to send redirect
     * @param tokens TokenInternalDto containing access and refresh tokens
     * @throws IOException if redirect fails
     */
    private void redirectToFrontend(HttpServletRequest request, HttpServletResponse response,
                                     TokenInternalDto tokens) throws IOException {
        // Build redirect URL with tokens as query parameters
        // UriComponentsBuilder safely encodes query parameters
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/callback")
                .queryParam("access_token", tokens.getAccessToken())
                .queryParam("refresh_token", tokens.getRefreshToken())
                // Calculate seconds until token expires (frontend uses this for countdown)
                .queryParam("expires_in", Duration.between(LocalDateTime.now(),
                        tokens.getAccessTokenExpiry()).getSeconds())
                .build().toUriString();

        log.debug("Redirecting to frontend: {}", frontendUrl + "/oauth2/callback");

        // Send HTTP 302 redirect response
        // Browser will automatically navigate to the redirect URL
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    /**
     * Check if Request is from API Client
     *
     * WHAT THIS DOES:
     * Determines if the client wants JSON response or browser redirect.
     *
     * LOGIC:
     * - If "Accept: application/json" header present → API client (mobile/SPA)
     * - Otherwise → Browser client (standard OAuth2 flow)
     *
     * @param request HTTP request to check
     * @return true if Accept header contains "application/json"
     */
    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        // Check if client explicitly requests JSON response
        return acceptHeader != null && acceptHeader.contains("application/json");
    }

    /**
     * Extract Client IP Address
     *
     * WHAT THIS DOES:
     * Gets the real client IP address, even when behind proxies/load balancers.
     *
     * HOW IT WORKS:
     * 1. First check X-Forwarded-For header (set by proxies/load balancers)
     *    - Format: "client-ip, proxy1-ip, proxy2-ip"
     *    - First IP is the original client IP
     * 2. If not present, use request.getRemoteAddr() (direct connection)
     *
     * WHY THIS IS NEEDED:
     * When deployed on Render with API Gateway:
     * - Direct connection: Auth Service ← API Gateway ← User
     * - request.getRemoteAddr() returns Gateway's IP, not user's IP
     * - Gateway adds X-Forwarded-For with user's real IP
     * - We need real IP for audit logging and security
     *
     * EXAMPLE:
     * X-Forwarded-For: "203.45.67.89, 10.0.1.5, 10.0.2.10"
     * Returns: "203.45.67.89" (user's actual IP)
     *
     * @param request HTTP request to extract IP from
     * @return Client IP address as string
     */
    private String getClientIp(HttpServletRequest request) {
        // Check if request went through proxy/load balancer
        String xForwardedFor = request.getHeader("X-Forwarded-For");

        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            // X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
            // Split by comma and take first IP (original client)
            return xForwardedFor.split(",")[0].trim();
        }

        // No proxy - return direct connection IP
        return request.getRemoteAddr();
    }
}
