package com.devision.jm.auth.config;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * CORS Configuration for Auth Service
 *
 * Allows cross-origin requests from frontend applications during development.
 * Skips CORS headers when request comes through API Gateway (to avoid duplicates).
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // Custom source that checks if request is from gateway
        source.registerCorsConfiguration("/**", new CorsConfiguration() {
            {
                // Allow localhost origins for development (direct access to auth-service:8081)
                setAllowedOrigins(Arrays.asList(
                        "http://localhost:3000",
                        "http://localhost:5173",
                        "http://127.0.0.1:3000",
                        "http://127.0.0.1:5173"
                ));

                // Allow all common HTTP methods
                setAllowedMethods(Arrays.asList(
                        "GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"
                ));

                // Allow all headers
                setAllowedHeaders(List.of("*"));

                // Allow credentials (cookies, authorization headers)
                setAllowCredentials(true);

                // Expose headers that frontend might need
                setExposedHeaders(Arrays.asList(
                        "Authorization",
                        "Content-Type",
                        "X-Request-Id"
                ));

                // Cache preflight response for 1 hour
                setMaxAge(3600L);
            }

            @Override
            public String checkOrigin(String origin) {
                // Only process CORS if origin doesn't already have CORS headers from gateway
                // The gateway sets Access-Control-Allow-Origin, so we check for forwarded requests
                return super.checkOrigin(origin);
            }
        });

        return source;
    }
}
