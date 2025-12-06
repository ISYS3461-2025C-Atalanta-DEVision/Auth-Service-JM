package com.devision.jm.auth.event;

/**
 * Kafka Topic Constants
 *
 * Centralized topic names for consistent messaging across services.
 * Topics are organized by domain for clear separation of concerns.
 */
public final class KafkaTopics {

    private KafkaTopics() {
        // Prevent instantiation
    }

    // ==================== AUTH SERVICE TOPICS ====================

    /**
     * User lifecycle events (registration, activation, deletion)
     * Consumers: Profile Service, Notification Service
     */
    public static final String USER_EVENTS = "devision.user.events";

    /**
     * Authentication events (login, logout, token operations)
     * Consumers: Profile Service (update last login), Audit Service
     */
    public static final String AUTH_EVENTS = "devision.auth.events";

    /**
     * Notification requests (emails, SMS, push notifications)
     * Consumers: Notification Service
     */
    public static final String NOTIFICATION_EVENTS = "devision.notification.events";

    // ==================== JOB MANAGER TOPICS ====================

    /**
     * Job post events (created, updated, expired)
     * Consumers: Search Service, Notification Service
     */
    public static final String JOB_EVENTS = "devision.job.events";

    /**
     * Company profile events
     * Consumers: Search Service
     */
    public static final String COMPANY_EVENTS = "devision.company.events";

    // ==================== JOB APPLICANT TOPICS ====================

    /**
     * Application events (submitted, reviewed, accepted, rejected)
     * Consumers: Notification Service, Analytics Service
     */
    public static final String APPLICATION_EVENTS = "devision.application.events";

    /**
     * Profile events (created, updated)
     * Consumers: Search Service
     */
    public static final String PROFILE_EVENTS = "devision.profile.events";
}
