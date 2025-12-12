package com.devision.jm.auth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

/**
 * Auth Service Application
 *
 * Microservice responsible for:
 * - Company Registration (1.1.1 - 1.3.3)
 * - Company Login with JWE (2.1.1 - 2.3.3)
 * - Admin Authentication
 * - Token management (generation, validation, refresh, revocation)
 * - Password management (reset, change with notifications)
 *
 * Architecture: Ultimo Level Microservice (A.3.1)
 * - Bounded context: Authentication & Authorization
 * - Internal/External API separation (A.2.3)
 * - DTO organization into internal/external (A.2.6)
 * - Redis integration for token revocation (2.3.2)
 * - Kafka integration for notifications (A.3.2)
 */
@SpringBootApplication
@EnableDiscoveryClient
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }
}
