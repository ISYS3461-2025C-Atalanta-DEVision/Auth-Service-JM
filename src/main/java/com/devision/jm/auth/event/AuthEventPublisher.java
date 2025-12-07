package com.devision.jm.auth.event;

import com.devision.jm.auth.model.entity.User;
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
 * This is a stub implementation that logs events instead of publishing to Kafka.
 * When Kafka is enabled, restore the full implementation from git history.
 *
 * Event Flow (when enabled):
 * Auth Service -> Kafka -> Profile Service (update last login)
 *                      -> Notification Service (send emails)
 *                      -> Audit Service (log activities)
 */
@Slf4j
@Service
public class AuthEventPublisher {

    // ==================== USER LIFECYCLE EVENTS ====================

    public void publishUserRegistered(User user) {
        log.info("[KAFKA DISABLED] Would publish USER_REGISTERED event for user: {}", user.getEmail());
    }

    public void publishUserActivated(User user) {
        log.info("[KAFKA DISABLED] Would publish USER_ACTIVATED event for user: {}", user.getEmail());
    }

    // ==================== AUTHENTICATION EVENTS ====================

    public void publishLoginSuccess(User user, String ipAddress, String userAgent) {
        log.info("[KAFKA DISABLED] Would publish LOGIN_SUCCESS event for user: {}", user.getEmail());
    }

    public void publishLoginFailed(String email, String reason, String ipAddress) {
        log.info("[KAFKA DISABLED] Would publish LOGIN_FAILED event for email: {}", email);
    }

    public void publishLogout(User user) {
        log.info("[KAFKA DISABLED] Would publish LOGOUT event for user: {}", user.getEmail());
    }

    public void publishTokenRevoked(User user, String tokenId) {
        log.info("[KAFKA DISABLED] Would publish TOKEN_REVOKED event for user: {}", user.getEmail());
    }

    // ==================== PASSWORD EVENTS ====================

    public void publishPasswordResetRequested(User user, String resetToken) {
        log.info("[KAFKA DISABLED] Would publish PASSWORD_RESET_REQUESTED event for user: {}", user.getEmail());
    }

    public void publishPasswordResetCompleted(User user) {
        log.info("[KAFKA DISABLED] Would publish PASSWORD_RESET_COMPLETED event for user: {}", user.getEmail());
    }

    // ==================== NOTIFICATION EVENTS ====================

    public void publishNotificationEvent(AuthEvent.EventType type, User user, Map<String, Object> additionalData) {
        log.info("[KAFKA DISABLED] Would publish notification event {} for user: {}", type, user.getEmail());
    }
}
