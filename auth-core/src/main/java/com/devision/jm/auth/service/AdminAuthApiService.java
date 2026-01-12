package com.devision.jm.auth.service;

import com.devision.jm.auth.api.external.dto.AdminUserResponse;
import com.devision.jm.auth.api.external.dto.LoginRequest;
import com.devision.jm.auth.api.external.dto.LoginResponse;
import com.devision.jm.auth.api.external.interfaces.AdminAuthApi;
import com.devision.jm.auth.api.external.interfaces.AuthenticationApi;
import com.devision.jm.auth.api.internal.dto.UserDeletedEvent;
import com.devision.jm.auth.api.internal.interfaces.KafkaProducerService;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.model.enums.AccountStatus;
import com.devision.jm.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

/**
 * Admin Auth API Service
 *
 * Implements admin operations for company account management.
 * Used by JA team via external API key authentication.
 *
 * Microservice Architecture (A.3.2):
 * - Publishes UserDeletedEvent to Kafka when company is deleted
 * - Profile Service and other services consume to clean up data
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AdminAuthApiService implements AdminAuthApi {

    private final UserRepository userRepository;
    private final AuthenticationApi authenticationService;
    private final KafkaProducerService kafkaProducerService;

    @Value("${kafka.enabled:false}")
    private boolean kafkaEnabled;

    @Override
    public LoginResponse adminLogin(LoginRequest request, String ipAddress) {
        return authenticationService.login(request, ipAddress);
    }

    @Override
    public AdminUserResponse deactivateCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.setStatus(AccountStatus.DEACTIVATED);
        userRepository.save(user);

        log.info("Company deactivated: userId={}, email={}", userId, user.getEmail());

        return AdminUserResponse.builder()
                .userId(userId)
                .email(user.getEmail())
                .status(AccountStatus.DEACTIVATED.name())
                .message("Company account deactivated successfully")
                .build();
    }

    @Override
    public AdminUserResponse activateCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        user.setStatus(AccountStatus.ACTIVE);
        userRepository.save(user);

        log.info("Company activated: userId={}, email={}", userId, user.getEmail());

        return AdminUserResponse.builder()
                .userId(userId)
                .email(user.getEmail())
                .status(AccountStatus.ACTIVE.name())
                .message("Company account activated successfully")
                .build();
    }

    @Override
    public void deleteCompany(String userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + userId));

        String email = user.getEmail();

        // Delete user from Auth DB
        userRepository.delete(user);
        log.info("Company deleted from Auth DB: userId={}, email={}", userId, email);

        // Publish UserDeletedEvent to Kafka for other services to clean up
        // Profile Service will delete profile and events
        // File Service will delete S3 files (avatars, event media)
        publishUserDeletedEvent(userId, email);
    }

    /**
     * Publish UserDeletedEvent to Kafka
     *
     * Other services (Profile, File, etc.) consume this event
     * to clean up user-related data.
     */
    private void publishUserDeletedEvent(String userId, String email) {
        if (!kafkaEnabled) {
            log.warn("Kafka disabled. UserDeletedEvent not published for userId={}. " +
                    "Profile and related data may be orphaned.", userId);
            return;
        }

        try {
            UserDeletedEvent event = UserDeletedEvent.builder()
                    .userId(userId)
                    .email(email)
                    .reason("Admin deletion")
                    .deletedAt(LocalDateTime.now())
                    .build();

            kafkaProducerService.publishUserDeletedEvent(event);
            log.info("Published UserDeletedEvent for userId={}", userId);

        } catch (Exception e) {
            // Log error but don't fail the delete operation
            // Profile data will be orphaned but auth deletion succeeded
            log.error("Failed to publish UserDeletedEvent for userId={}: {}",
                    userId, e.getMessage(), e);
        }
    }
}
