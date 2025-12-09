package com.devision.jm.auth.event;

import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Auth Event Publisher Service
 *
 * Publishes authentication events for consumption by other services.
 * Implements async event publishing for non-blocking operations (A.3.2 requirement).
 *
 * NOTE: KAFKA IS CURRENTLY DISABLED
 * Events are handled locally via EmailService.
 * When Kafka is enabled, events will also be published to Kafka topics.
 *
 * Event Flow (when enabled):
 * Auth Service -> Kafka -> Profile Service (update last login)
 *                      -> Notification Service (send emails)
 *                      -> Audit Service (log activities)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final EmailService emailService;

    // ==================== USER LIFECYCLE EVENTS ====================

    /**
     * Publish USER_REGISTERED event
     * Triggers activation email (Requirement 1.1.3)
     */
    public void publishUserRegistered(User user) {
        log.info("[EVENT] USER_REGISTERED for user: {}", user.getEmail());

        // Send activation email (Requirement 1.1.3)
        if (user.getActivationToken() != null) {
            try {
                emailService.sendActivationEmail(user, user.getActivationToken());
                log.info("Activation email triggered for: {}", user.getEmail());
            } catch (Exception e) {
                log.error("Failed to send activation email to {}: {}", user.getEmail(), e.getMessage());
            }
        }

        // TODO: When Kafka is enabled, publish to kafka topic
        log.debug("[KAFKA DISABLED] Would publish USER_REGISTERED event to Kafka");
    }

    /**
     * Publish USER_ACTIVATED event
     * Triggers welcome email
     */
    public void publishUserActivated(User user) {
        log.info("[EVENT] USER_ACTIVATED for user: {}", user.getEmail());

        // Send welcome email
        try {
            emailService.sendWelcomeEmail(user);
            log.info("Welcome email triggered for: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send welcome email to {}: {}", user.getEmail(), e.getMessage());
        }

        // TODO: When Kafka is enabled, publish to kafka topic
        log.debug("[KAFKA DISABLED] Would publish USER_ACTIVATED event to Kafka");
    }

    // ==================== AUTHENTICATION EVENTS ====================

    public void publishLoginSuccess(User user, String ipAddress, String userAgent) {
        log.info("[EVENT] LOGIN_SUCCESS for user: {} from IP: {}", user.getEmail(), ipAddress);
        // TODO: When Kafka is enabled, publish to kafka topic for audit logging
        log.debug("[KAFKA DISABLED] Would publish LOGIN_SUCCESS event to Kafka");
    }

    public void publishLoginFailed(String email, String reason, String ipAddress) {
        log.info("[EVENT] LOGIN_FAILED for email: {} reason: {} from IP: {}", email, reason, ipAddress);
        // TODO: When Kafka is enabled, publish to kafka topic for audit logging
        log.debug("[KAFKA DISABLED] Would publish LOGIN_FAILED event to Kafka");
    }

    public void publishLogout(User user) {
        log.info("[EVENT] LOGOUT for user: {}", user.getEmail());
        log.debug("[KAFKA DISABLED] Would publish LOGOUT event to Kafka");
    }

    public void publishTokenRevoked(User user, String tokenId) {
        log.info("[EVENT] TOKEN_REVOKED for user: {}", user.getEmail());
        log.debug("[KAFKA DISABLED] Would publish TOKEN_REVOKED event to Kafka");
    }

    // ==================== PASSWORD EVENTS ====================

    /**
     * Publish PASSWORD_RESET_REQUESTED event
     * Triggers password reset email
     */
    public void publishPasswordResetRequested(User user, String resetToken) {
        log.info("[EVENT] PASSWORD_RESET_REQUESTED for user: {}", user.getEmail());

        // Send password reset email
        try {
            emailService.sendPasswordResetEmail(user, resetToken);
            log.info("Password reset email triggered for: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", user.getEmail(), e.getMessage());
        }

        log.debug("[KAFKA DISABLED] Would publish PASSWORD_RESET_REQUESTED event to Kafka");
    }

    /**
     * Publish PASSWORD_RESET_COMPLETED event
     * Triggers password change confirmation email
     */
    public void publishPasswordResetCompleted(User user) {
        log.info("[EVENT] PASSWORD_RESET_COMPLETED for user: {}", user.getEmail());

        // Send password change confirmation
        try {
            emailService.sendPasswordChangeConfirmation(user);
            log.info("Password change confirmation email triggered for: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send password change confirmation to {}: {}", user.getEmail(), e.getMessage());
        }

        log.debug("[KAFKA DISABLED] Would publish PASSWORD_RESET_COMPLETED event to Kafka");
    }

    // ==================== NOTIFICATION EVENTS ====================

    /**
     * Publish notification events
     * Handles subscription warnings and other notifications (Requirement 6.1.2)
     */
    public void publishNotificationEvent(AuthEvent.EventType type, User user, Map<String, Object> additionalData) {
        log.info("[EVENT] {} for user: {}", type, user.getEmail());

        try {
            switch (type) {
                case PASSWORD_CHANGED -> emailService.sendPasswordChangeConfirmation(user);
                case SUBSCRIPTION_EXPIRING -> {
                    int daysRemaining = (int) additionalData.getOrDefault("daysRemaining", 7);
                    emailService.sendSubscriptionExpirationWarning(user, daysRemaining);
                }
                case SUBSCRIPTION_EXPIRED -> emailService.sendSubscriptionExpiredNotification(user);
                default -> log.debug("No email handler for event type: {}", type);
            }
        } catch (Exception e) {
            log.error("Failed to send notification email for {} to {}: {}", type, user.getEmail(), e.getMessage());
        }

        log.debug("[KAFKA DISABLED] Would publish {} event to Kafka", type);
    }

    // ==================== SUBSCRIPTION EVENTS (Requirement 6.1.2) ====================

    /**
     * Publish subscription expiration warning
     * Called 7 days before subscription expires
     */
    public void publishSubscriptionExpiringWarning(User user, int daysRemaining) {
        log.info("[EVENT] SUBSCRIPTION_EXPIRING for user: {} ({} days remaining)", user.getEmail(), daysRemaining);

        try {
            emailService.sendSubscriptionExpirationWarning(user, daysRemaining);
            log.info("Subscription warning email triggered for: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send subscription warning to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    /**
     * Publish subscription expired notification
     * Called when subscription officially expires
     */
    public void publishSubscriptionExpired(User user) {
        log.info("[EVENT] SUBSCRIPTION_EXPIRED for user: {}", user.getEmail());

        try {
            emailService.sendSubscriptionExpiredNotification(user);
            log.info("Subscription expired email triggered for: {}", user.getEmail());
        } catch (Exception e) {
            log.error("Failed to send subscription expired notification to {}: {}", user.getEmail(), e.getMessage());
        }
    }
}
