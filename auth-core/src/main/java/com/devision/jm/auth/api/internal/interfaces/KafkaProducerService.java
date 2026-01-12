package com.devision.jm.auth.api.internal.interfaces;

import com.devision.jm.auth.api.internal.dto.UserCreatedEvent;
import com.devision.jm.auth.api.internal.dto.UserDeletedEvent;

/**
 * Kafka Producer Service (Internal API)
 *
 * Internal service for publishing events to Kafka.
 * NOT accessible by other modules - only used within auth-core.
 *
 * Implements Microservice Architecture (A.3.2):
 * - Communication among microservices via Message Broker (Kafka)
 */
public interface KafkaProducerService {

    /**
     * Publish user created event to Kafka
     *
     * Topic: user-created
     * Consumer: Profile Service
     *
     * @param event User created event containing profile data
     */
    void publishUserCreatedEvent(UserCreatedEvent event);

    /**
     * Publish user deleted event to Kafka
     *
     * Topic: user-deleted
     * Consumers: Profile Service, File Service, etc.
     *
     * @param event User deleted event for cleanup
     */
    void publishUserDeletedEvent(UserDeletedEvent event);
}
