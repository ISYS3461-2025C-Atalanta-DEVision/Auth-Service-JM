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
 * OAuth2 Authentication Success Handler
 *
 * Handles successful OAuth2 authentication (1.3.1, 2.3.1).
 * - Generates JWT tokens for the authenticated user
 * - Redirects to frontend with tokens in URL parameters
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final OAuth2AuthenticationService oauth2AuthenticationService;
    private final ObjectMapper objectMapper;

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                         Authentication authentication) throws IOException, ServletException {

        OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
        String email = oauth2User.getAttribute("email");

        log.info("OAuth2 authentication successful for: {}", email);

        try {
            // Get client IP and device info
            String ipAddress = getClientIp(request);
            String deviceInfo = request.getHeader("User-Agent");

            // Generate JWT tokens
            TokenInternalDto tokens = oauth2AuthenticationService.generateTokensForOAuth2User(
                    email, ipAddress, deviceInfo);

            // Check if this is an API request (Accept: application/json)
            if (isApiRequest(request)) {
                // Return JSON response for API clients
                sendJsonResponse(response, tokens);
            } else {
                // Redirect to frontend with tokens for browser-based flow
                redirectToFrontend(request, response, tokens);
            }

        } catch (Exception e) {
            log.error("Failed to process OAuth2 success: {}", e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    "Failed to process authentication");
        }
    }

    private void sendJsonResponse(HttpServletResponse response, TokenInternalDto tokens) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        Map<String, Object> responseBody = Map.of(
                "success", true,
                "message", "OAuth2 authentication successful",
                "data", Map.of(
                        "accessToken", tokens.getAccessToken(),
                        "refreshToken", tokens.getRefreshToken(),
                        "tokenType", "Bearer",
                        "expiresIn", Duration.between(LocalDateTime.now(),
                                tokens.getAccessTokenExpiry()).getSeconds(),
                        "refreshExpiresIn", Duration.between(LocalDateTime.now(),
                                tokens.getRefreshTokenExpiry()).getSeconds()
                )
        );

        response.getWriter().write(objectMapper.writeValueAsString(responseBody));
    }

    private void redirectToFrontend(HttpServletRequest request, HttpServletResponse response,
                                     TokenInternalDto tokens) throws IOException {
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/callback")
                .queryParam("access_token", tokens.getAccessToken())
                .queryParam("refresh_token", tokens.getRefreshToken())
                .queryParam("expires_in", Duration.between(LocalDateTime.now(),
                        tokens.getAccessTokenExpiry()).getSeconds())
                .build().toUriString();

        log.debug("Redirecting to frontend: {}", frontendUrl + "/oauth2/callback");
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }

    private boolean isApiRequest(HttpServletRequest request) {
        String acceptHeader = request.getHeader("Accept");
        return acceptHeader != null && acceptHeader.contains("application/json");
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
