package com.devision.jm.auth.event;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.Map;

/**
 * Base Event class for Kafka messages
 *
 * All events published to Kafka follow this structure.
 * Used for inter-service communication (A.3.2 requirement).
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthEvent {

    /**
     * Event types for authentication-related events
     */
    public enum EventType {
        // User lifecycle events
        USER_REGISTERED,
        USER_ACTIVATED,
        USER_DEACTIVATED,
        USER_DELETED,
        USER_PROFILE_UPDATED,

        // Authentication events
        LOGIN_SUCCESS,
        LOGIN_FAILED,
        LOGOUT,
        TOKEN_REFRESHED,
        TOKEN_REVOKED,

        // Password events
        PASSWORD_RESET_REQUESTED,
        PASSWORD_RESET_COMPLETED,
        PASSWORD_CHANGED,

        // Notification triggers
        SEND_WELCOME_EMAIL,
        SEND_ACTIVATION_EMAIL,
        SEND_PASSWORD_RESET_EMAIL,
        SEND_LOGIN_ALERT,

        // Subscription events (Requirement 6.1.2)
        SUBSCRIPTION_EXPIRING,
        SUBSCRIPTION_EXPIRED
    }

    /**
     * Unique event identifier
     */
    private String eventId;

    /**
     * Type of event
     */
    private EventType eventType;

    /**
     * User ID associated with this event (String type for MongoDB ObjectId)
     */
    private String userId;

    /**
     * User email (for notification purposes)
     */
    private String userEmail;

    /**
     * Timestamp when event occurred
     */
    private Instant timestamp;

    /**
     * Source service that generated this event
     */
    private String source;

    /**
     * Additional event-specific data
     */
    private Map<String, Object> payload;
}
