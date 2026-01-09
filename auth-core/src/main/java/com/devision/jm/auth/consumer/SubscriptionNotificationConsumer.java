package com.devision.jm.auth.consumer;

import com.devision.jm.auth.api.internal.dto.SubscriptionNotificationEvent;
import com.devision.jm.auth.api.internal.interfaces.EmailService;
import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Service;

/**
 * Kafka Consumer for Subscription Notification Events
 *
 * Listens to the "subscription-notifications" topic from Payment Service.
 * Sends email notifications when subscription is expiring or expired.
 * Only loaded when kafka.enabled=true (KAFKA_ENABLED env var).
 *
 * Flow:
 * 1. Payment Service scheduled job detects expiring/expired subscriptions
 * 2. Payment Service publishes SubscriptionNotificationEvent to Kafka
 * 3. This consumer receives the event
 * 4. Sends appropriate email (warning or expired)
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(name = "kafka.enabled", havingValue = "true")
public class SubscriptionNotificationConsumer {

    private final UserRepository userRepository;
    private final EmailService emailService;
    private final ObjectMapper objectMapper;

    /**
     * Consume SubscriptionNotificationEvent from Kafka
     *
     * Topic: subscription-notifications
     * Group: auth-service-group
     */
    @KafkaListener(
            topics = "subscription-notifications",
            groupId = "auth-service-group"
    )
    public void consumeSubscriptionNotificationEvent(String message) {
        log.info("========== RECEIVED SUBSCRIPTION NOTIFICATION EVENT ==========");
        log.info("Message: {}", message);

        try {
            // Deserialize JSON message to DTO
            SubscriptionNotificationEvent event = objectMapper.readValue(message, SubscriptionNotificationEvent.class);

            log.info("Processing SubscriptionNotificationEvent: eventType={}, userId={}, daysLeft={}",
                    event.getEventType(), event.getUserId(), event.getDaysLeft());

            // Find user by ID
            User user = userRepository.findById(event.getUserId()).orElse(null);

            if (user == null) {
                log.error("User not found for userId: {}. Cannot send notification email.", event.getUserId());
                return;
            }

            // Send appropriate email based on event type
            if ("ENDING_SOON".equals(event.getEventType())) {
                emailService.sendSubscriptionExpirationWarning(user, event.getDaysLeft());
                log.info("✅ Sent ENDING_SOON email to userId={}, email={}", user.getId(), user.getEmail());
            } else if ("ENDED".equals(event.getEventType())) {
                emailService.sendSubscriptionExpiredNotification(user);
                log.info("✅ Sent ENDED email to userId={}, email={}", user.getId(), user.getEmail());
            } else {
                log.warn("Unknown eventType: {}", event.getEventType());
            }

            log.info("========== SUBSCRIPTION NOTIFICATION PROCESSED ==========");

        } catch (Exception e) {
            log.error("Failed to process SubscriptionNotificationEvent: {}", e.getMessage(), e);
        }
    }
}
