package com.devision.jm.auth.config;

/**
 * Kafka Configuration
 *
 * Configures Kafka for inter-service communication (A.3.2).
 *
 * NOTE: KAFKA IS CURRENTLY DISABLED
 * To enable:
 * 1. Add spring-kafka dependency to pom.xml
 * 2. Remove KafkaAutoConfiguration from exclusions in application.yml
 * 3. Uncomment the code below
 *
 * Event Flow:
 * Auth Service -> Kafka -> Profile Service (create profile)
 *                      -> Notification Service (send emails)
 *                      -> Audit Service (log activities)
 */
public class KafkaConfig {
    // KAFKA DISABLED - All configuration commented out
    // See git history for full implementation
}
