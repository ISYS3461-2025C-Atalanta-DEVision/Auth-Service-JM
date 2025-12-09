package com.devision.jm.auth.config;

import com.devision.jm.auth.filter.InternalApiKeyValidationFilter;
import com.devision.jm.auth.filter.JwtAuthenticationFilter;
import com.devision.jm.auth.service.impl.OAuth2AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;

/**
 * Security Configuration
 *
 * Configures Spring Security for JWT-based authentication.
 * Implements stateless session management for microservices architecture.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final InternalApiKeyValidationFilter internalApiKeyValidationFilter;
    private final OAuth2AuthenticationService oauth2AuthenticationService;
    private final OAuth2SuccessHandler oauth2SuccessHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // Disable CORS at service level - Gateway handles CORS
                .cors(AbstractHttpConfigurer::disable)

                // Disable CSRF for stateless API
                .csrf(AbstractHttpConfigurer::disable)

                // Allow H2 console frames (development only)
                .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

                // Stateless session management
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                // Authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints
                        .requestMatchers(
                                "/",
                                "/api/auth/register",
                                "/api/auth/login",
                                "/api/auth/refresh",
                                "/api/auth/activate/**",
                                "/api/auth/forgot-password",
                                "/api/auth/reset-password/**",
                                "/api/auth/validate",
                                "/api/auth/countries",
                                "/api/auth/admin/login",
                                // OAuth2 endpoints
                                "/oauth2/**",
                                "/login/oauth2/**",
                                // Actuator endpoints
                                "/actuator/**"
                        ).permitAll()

                        // Admin endpoints require ADMIN role
                        .requestMatchers("/api/admin/**").hasRole("ADMIN")

                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                // OAuth2 Login Configuration (1.3.1, 2.3.1 - Google SSO)
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oauth2AuthenticationService))
                        .successHandler(oauth2SuccessHandler)
                )

                // Add Internal API Key filter first (validates requests from Gateway)
                .addFilterBefore(internalApiKeyValidationFilter, SecurityContextHolderFilter.class)

                // Add JWT filter before UsernamePasswordAuthenticationFilter
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public AuthenticationManager authenticationManager(
            AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }
}
