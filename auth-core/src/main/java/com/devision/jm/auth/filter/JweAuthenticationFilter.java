package com.devision.jm.auth.filter;

import com.devision.jm.auth.config.JweConfig;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.DirectDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.text.ParseException;
import java.util.Date;
import java.util.List;

/**
 * JWE Authentication Filter
 *
 * Intercepts requests to validate JWE (encrypted) tokens.
 * Organized separately from tier structure (A.1.3).
 *
 * Implements:
 * - JWE token decryption and validation (2.2.1)
 * - Token revocation check via Redis (2.3.2)
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class JweAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String REVOKED_TOKEN_PREFIX = "revoked:";

    private final JweConfig jweConfig;
    private final RedisTemplate<String, String> redisTemplate;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String jwe = extractJweFromRequest(request);

            if (StringUtils.hasText(jwe)) {
                // Decrypt and validate JWE token (2.2.1)
                JWTClaimsSet claims = decryptAndValidateToken(jwe);

                if (claims != null) {
                    // Check if token is revoked in Redis (2.3.2)
                    if (isTokenRevoked(jwe)) {
                        log.warn("Attempted use of revoked token");
                        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        response.setContentType("application/json");
                        response.getWriter().write("{\"error\": \"Token has been revoked\"}");
                        return;
                    }

                    // Check if token is expired
                    if (claims.getExpirationTime() != null && claims.getExpirationTime().before(new Date())) {
                        log.warn("JWE token has expired");
                        response.setHeader("X-Token-Expired", "true");
                        filterChain.doFilter(request, response);
                        return;
                    }

                    // Extract claims
                    String userId = claims.getStringClaim("userId");
                    String email = claims.getStringClaim("email");
                    String role = claims.getStringClaim("role");

                    // Create authentication token
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(
                                    email,
                                    null,
                                    List.of(new SimpleGrantedAuthority("ROLE_" + role))
                            );

                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set authentication in security context
                    SecurityContextHolder.getContext().setAuthentication(authentication);

                    // Add user info to request attributes for controllers
                    request.setAttribute("userId", userId);
                    request.setAttribute("userEmail", email);
                    request.setAttribute("userRole", role);
                }
            }
        } catch (Exception e) {
            log.debug("Cannot set user authentication: {}", e.getMessage());
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Extract JWE token from Authorization header
     */
    private String extractJweFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }

    /**
     * Decrypt and validate JWE token (2.2.1)
     * Returns claims if valid, null if invalid
     */
    private JWTClaimsSet decryptAndValidateToken(String token) {
        try {
            // Parse the JWE token
            EncryptedJWT encryptedJWT = EncryptedJWT.parse(token);

            // Decrypt with AES-256 key
            DirectDecrypter decrypter = new DirectDecrypter(jweConfig.getEncryptionKey());
            encryptedJWT.decrypt(decrypter);

            // Return decrypted claims
            return encryptedJWT.getJWTClaimsSet();

        } catch (ParseException e) {
            log.debug("Invalid JWE token format: {}", e.getMessage());
            return null;
        } catch (JOSEException e) {
            log.debug("Failed to decrypt JWE token: {}", e.getMessage());
            return null;
        }
    }

    /**
     * Check if token is revoked in Redis (2.3.2)
     */
    private boolean isTokenRevoked(String token) {
        try {
            String key = REVOKED_TOKEN_PREFIX + token;
            return Boolean.TRUE.equals(redisTemplate.hasKey(key));
        } catch (Exception e) {
            // Fail-open for availability (allow request to proceed)
            // Log error but don't block the request
            log.error("Redis unavailable for token revocation check: {}", e.getMessage());
            return false;
        }
    }
}
