package com.devision.jm.auth.event;

import com.devision.jm.auth.model.entity.User;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

/**
 * Kafka Event Publisher Service
 *
 * Publishes authentication events to Kafka topics for consumption by other services.
 * Implements async event publishing for non-blocking operations (A.3.2 requirement).
 *
 * Event Flow:
 * Auth Service → Kafka → Profile Service (update last login)
 *                     → Notification Service (send emails)
 *                     → Audit Service (log activities)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthEventPublisher {

    private static final String SOURCE_SERVICE = "AUTH-SERVICE";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    // ==================== USER LIFECYCLE EVENTS ====================

    /**
     * Publish USER_REGISTERED event when a new user registers
     *
     * Consumers:
     * - Profile Service: Creates initial profile
     * - Notification Service: Sends welcome email
     */
    @Async
    public void publishUserRegistered(User user) {
        AuthEvent event = buildEvent(AuthEvent.EventType.USER_REGISTERED, user);
        event.setPayload(Map.of(
                "companyName", user.getCompanyName() != null ? user.getCompanyName() : "",
                "country", user.getCountry(),
                "role", user.getRole().name()
        ));

        publishToTopic(KafkaTopics.USER_EVENTS, user.getId().toString(), event);

        // Also trigger welcome email
        publishNotificationEvent(AuthEvent.EventType.SEND_WELCOME_EMAIL, user,
                Map.of("activationToken", user.getActivationToken() != null ? user.getActivationToken() : ""));
    }

    /**
     * Publish USER_ACTIVATED event when user activates their account
     *
     * Consumers:
     * - Profile Service: Updates profile status
     * - Notification Service: Sends activation confirmation
     */
    @Async
    public void publishUserActivated(User user) {
        AuthEvent event = buildEvent(AuthEvent.EventType.USER_ACTIVATED, user);
        publishToTopic(KafkaTopics.USER_EVENTS, user.getId().toString(), event);
    }

    // ==================== AUTHENTICATION EVENTS ====================

    /**
     * Publish LOGIN_SUCCESS event when user logs in successfully
     *
     * Consumers:
     * - Profile Service: Updates last login timestamp
     * - Audit Service: Logs successful login
     * - Notification Service: (Optional) Sends login alert for new device
     */
    @Async
    public void publishLoginSuccess(User user, String ipAddress, String userAgent) {
        AuthEvent event = buildEvent(AuthEvent.EventType.LOGIN_SUCCESS, user);
        event.setPayload(Map.of(
                "ipAddress", ipAddress != null ? ipAddress : "unknown",
                "userAgent", userAgent != null ? userAgent : "unknown",
                "loginTime", Instant.now().toString()
        ));

        publishToTopic(KafkaTopics.AUTH_EVENTS, user.getId().toString(), event);
    }

    /**
     * Publish LOGIN_FAILED event when login fails
     *
     * Consumers:
     * - Audit Service: Logs failed attempt
     * - Security Service: Track brute force attempts
     */
    @Async
    public void publishLoginFailed(String email, String reason, String ipAddress) {
        AuthEvent event = AuthEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(AuthEvent.EventType.LOGIN_FAILED)
                .userEmail(email)
                .timestamp(Instant.now())
                .source(SOURCE_SERVICE)
                .payload(Map.of(
                        "reason", reason,
                        "ipAddress", ipAddress != null ? ipAddress : "unknown"
                ))
                .build();

        publishToTopic(KafkaTopics.AUTH_EVENTS, email, event);
    }

    /**
     * Publish LOGOUT event when user logs out
     *
     * Consumers:
     * - Audit Service: Logs logout
     */
    @Async
    public void publishLogout(User user) {
        AuthEvent event = buildEvent(AuthEvent.EventType.LOGOUT, user);
        publishToTopic(KafkaTopics.AUTH_EVENTS, user.getId().toString(), event);
    }

    /**
     * Publish TOKEN_REVOKED event when token is revoked (logout, security)
     *
     * Consumers:
     * - All services with token cache: Invalidate cached tokens
     */
    @Async
    public void publishTokenRevoked(User user, String tokenId) {
        AuthEvent event = buildEvent(AuthEvent.EventType.TOKEN_REVOKED, user);
        event.setPayload(Map.of("tokenId", tokenId));
        publishToTopic(KafkaTopics.AUTH_EVENTS, user.getId().toString(), event);
    }

    // ==================== PASSWORD EVENTS ====================

    /**
     * Publish PASSWORD_RESET_REQUESTED event
     *
     * Consumers:
     * - Notification Service: Sends password reset email
     */
    @Async
    public void publishPasswordResetRequested(User user, String resetToken) {
        AuthEvent event = buildEvent(AuthEvent.EventType.PASSWORD_RESET_REQUESTED, user);

        publishToTopic(KafkaTopics.AUTH_EVENTS, user.getId().toString(), event);

        // Trigger password reset email
        publishNotificationEvent(AuthEvent.EventType.SEND_PASSWORD_RESET_EMAIL, user,
                Map.of("resetToken", resetToken));
    }

    /**
     * Publish PASSWORD_RESET_COMPLETED event
     *
     * Consumers:
     * - Notification Service: Sends confirmation email
     * - Audit Service: Logs password change
     */
    @Async
    public void publishPasswordResetCompleted(User user) {
        AuthEvent event = buildEvent(AuthEvent.EventType.PASSWORD_RESET_COMPLETED, user);
        publishToTopic(KafkaTopics.AUTH_EVENTS, user.getId().toString(), event);
    }

    // ==================== NOTIFICATION EVENTS ====================

    /**
     * Publish notification event to trigger email/SMS/push
     */
    @Async
    public void publishNotificationEvent(AuthEvent.EventType type, User user, Map<String, Object> additionalData) {
        AuthEvent event = buildEvent(type, user);

        Map<String, Object> payload = new HashMap<>();
        payload.put("notificationType", getNotificationType(type));
        payload.put("recipientEmail", user.getEmail());
        payload.put("recipientName", user.getCompanyName() != null ? user.getCompanyName() : user.getEmail());
        if (additionalData != null) {
            payload.putAll(additionalData);
        }
        event.setPayload(payload);

        publishToTopic(KafkaTopics.NOTIFICATION_EVENTS, user.getId().toString(), event);
    }

    // ==================== HELPER METHODS ====================

    private AuthEvent buildEvent(AuthEvent.EventType eventType, User user) {
        return AuthEvent.builder()
                .eventId(UUID.randomUUID().toString())
                .eventType(eventType)
                .userId(user.getId())
                .userEmail(user.getEmail())
                .timestamp(Instant.now())
                .source(SOURCE_SERVICE)
                .build();
    }

    private void publishToTopic(String topic, String key, AuthEvent event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);

            CompletableFuture<SendResult<String, String>> future =
                    kafkaTemplate.send(topic, key, eventJson);

            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to publish event {} to topic {}: {}",
                            event.getEventType(), topic, ex.getMessage());
                } else {
                    log.info("Published event {} to topic {} [partition={}, offset={}]",
                            event.getEventType(), topic,
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                }
            });

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize event {}: {}", event.getEventType(), e.getMessage());
        }
    }

    private String getNotificationType(AuthEvent.EventType eventType) {
        return switch (eventType) {
            case SEND_WELCOME_EMAIL -> "WELCOME_EMAIL";
            case SEND_ACTIVATION_EMAIL -> "ACTIVATION_EMAIL";
            case SEND_PASSWORD_RESET_EMAIL -> "PASSWORD_RESET_EMAIL";
            case SEND_LOGIN_ALERT -> "LOGIN_ALERT";
            default -> "GENERAL";
        };
    }
}
