package com.devision.jm.auth.api.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Subscription Notification Event
 *
 * Consumed from Kafka topic "subscription-notifications" from Payment Service.
 * Used to send email notifications when subscription is expiring or expired.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SubscriptionNotificationEvent {

    /**
     * Event type: ENDING_SOON (7 days before) or ENDED (on expiry day)
     */
    private String eventType;

    /**
     * User ID (from Auth Service)
     */
    private String userId;

    /**
     * Plan type (PREMIUM)
     */
    private String planType;

    /**
     * Subscription end date
     */
    private LocalDate endDate;

    /**
     * Days remaining (7 for ENDING_SOON, 0 for ENDED)
     */
    private Integer daysLeft;

    /**
     * Timestamp when event occurred
     */
    private LocalDateTime occurredAt;
}
