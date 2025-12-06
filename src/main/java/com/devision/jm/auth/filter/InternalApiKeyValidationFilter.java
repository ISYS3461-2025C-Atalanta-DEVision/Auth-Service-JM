package com.devision.jm.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Internal API Key Validation Filter
 *
 * Validates that requests come from the API Gateway by checking
 * the X-Internal-Api-Key header. This prevents direct access to
 * the Auth Service bypassing the Gateway.
 *
 * Security: Rejects requests without valid internal API key in production.
 */
@Slf4j
@Component
@Order(1) // Run before other filters
public class InternalApiKeyValidationFilter extends OncePerRequestFilter {

    public static final String INTERNAL_API_KEY_HEADER = "X-Internal-Api-Key";

    // Endpoints that can be accessed without internal API key (for health checks, etc.)
    private static final List<String> ALLOWED_WITHOUT_KEY = List.of(
            "/actuator/health",
            "/actuator/info"
    );

    @Value("${internal.api-key}")
    private String expectedApiKey;

    @Value("${internal.api-key-validation.enabled:true}")
    private boolean validationEnabled;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();

        // Skip validation for allowed endpoints
        if (isAllowedWithoutKey(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Skip validation if disabled (for local development)
        if (!validationEnabled) {
            log.debug("Internal API key validation disabled, allowing request to: {}", path);
            filterChain.doFilter(request, response);
            return;
        }

        // Validate internal API key
        String providedApiKey = request.getHeader(INTERNAL_API_KEY_HEADER);

        if (providedApiKey == null || providedApiKey.isBlank()) {
            log.warn("Missing internal API key header for request to: {} from IP: {}",
                    path, request.getRemoteAddr());
            sendForbiddenResponse(response, "Missing internal API key");
            return;
        }

        if (!expectedApiKey.equals(providedApiKey)) {
            log.warn("Invalid internal API key for request to: {} from IP: {}",
                    path, request.getRemoteAddr());
            sendForbiddenResponse(response, "Invalid internal API key");
            return;
        }

        log.debug("Valid internal API key for request to: {}", path);
        filterChain.doFilter(request, response);
    }

    private boolean isAllowedWithoutKey(String path) {
        return ALLOWED_WITHOUT_KEY.stream().anyMatch(path::startsWith);
    }

    private void sendForbiddenResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType("application/json");
        response.getWriter().write(String.format(
                "{\"success\":false,\"message\":\"%s\",\"errorCode\":\"FORBIDDEN\"}", message));
    }
}
