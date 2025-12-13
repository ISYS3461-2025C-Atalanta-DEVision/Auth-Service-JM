package com.devision.jm.auth.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

/**
 * OAuth2 Authentication Failure Handler
 *
 * WHAT THIS DOES:
 * Handles OAuth2 authentication failures and redirects to frontend with error message.
 *
 * WHEN IT'S CALLED:
 * Automatically invoked by Spring Security when OAuth2 authentication fails:
 * 1. User cancels Google login
 * 2. Google rejects the authentication
 * 3. Exception thrown during user processing
 * 4. Exception thrown during token generation
 *
 * WHAT IT DOES:
 * 1. Logs the error
 * 2. Redirects to frontend with error parameter
 * 3. Frontend displays error message to user
 */
@Slf4j
@Component
public class OAuth2FailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Value("${app.frontend-url:http://localhost:3000}")
    private String frontendUrl;

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                         HttpServletResponse response,
                                         AuthenticationException exception) throws IOException, ServletException {

        log.error("OAuth2 authentication failed: {}", exception.getMessage(), exception);

        // Build redirect URL to frontend with error message
        String targetUrl = UriComponentsBuilder.fromUriString(frontendUrl + "/oauth2/callback")
                .queryParam("error", "authentication_failed")
                .queryParam("message", exception.getMessage())
                .build()
                .toUriString();

        // Redirect to frontend
        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}
