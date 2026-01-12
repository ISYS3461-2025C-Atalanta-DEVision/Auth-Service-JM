package com.devision.jm.auth.service;

import com.devision.jm.auth.api.internal.dto.UserCreatedEvent;
import com.devision.jm.auth.api.internal.dto.UserDeletedEvent;
import com.devision.jm.auth.api.internal.interfaces.KafkaProducerService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.support.SendResult;
import org.springframework.stereotype.Service;

import java.util.concurrent.CompletableFuture;

/**
 * Kafka Producer Service Implementation
 *
 * Publishes events to Kafka topics for inter-service communication.
 *
 * Implements Microservice Architecture (A.3.2):
 * - Communication among microservices via Message Broker (Kafka)
 *
 * Topics:
 * - user-created: Published when new user registers (consumed by Profile Service)
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class KafkaProducerServiceImpl implements KafkaProducerService {

    private static final String USER_CREATED_TOPIC = "user-created";
    private static final String USER_DELETED_TOPIC = "user-deleted";

    private final KafkaTemplate<String, String> kafkaTemplate;
    private final ObjectMapper objectMapper;

    /**
     * Publish user created event to Kafka
     *
     * Event is serialized to JSON and sent to "user-created" topic.
     * Profile Service consumes this event to create the user's profile.
     *
     * @param event User created event containing profile data
     */
    @Override
    public void publishUserCreatedEvent(UserCreatedEvent event) {
        try {
            // Serialize event to JSON
            String eventJson = objectMapper.writeValueAsString(event);

            // Send to Kafka with userId as key (ensures ordering for same user)
            CompletableFuture<SendResult<String, String>> future =
                    kafkaTemplate.send(USER_CREATED_TOPIC, event.getUserId(), eventJson);

            // Log success/failure asynchronously
            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to publish user-created event for userId {}: {}",
                            event.getUserId(), ex.getMessage());
                } else {
                    log.info("Published user-created event for userId {} to partition {} offset {}",
                            event.getUserId(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                }
            });

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize user-created event for userId {}: {}",
                    event.getUserId(), e.getMessage());
            throw new RuntimeException("Failed to serialize Kafka event", e);
        }
    }

    /**
     * Publish user deleted event to Kafka
     *
     * Event is serialized to JSON and sent to "user-deleted" topic.
     * Profile Service and other services consume this event to clean up user data.
     *
     * @param event User deleted event for cleanup
     */
    @Override
    public void publishUserDeletedEvent(UserDeletedEvent event) {
        try {
            // Serialize event to JSON
            String eventJson = objectMapper.writeValueAsString(event);

            // Send to Kafka with userId as key (ensures ordering for same user)
            CompletableFuture<SendResult<String, String>> future =
                    kafkaTemplate.send(USER_DELETED_TOPIC, event.getUserId(), eventJson);

            // Log success/failure asynchronously
            future.whenComplete((result, ex) -> {
                if (ex != null) {
                    log.error("Failed to publish user-deleted event for userId {}: {}",
                            event.getUserId(), ex.getMessage());
                } else {
                    log.info("Published user-deleted event for userId {} to partition {} offset {}",
                            event.getUserId(),
                            result.getRecordMetadata().partition(),
                            result.getRecordMetadata().offset());
                }
            });

        } catch (JsonProcessingException e) {
            log.error("Failed to serialize user-deleted event for userId {}: {}",
                    event.getUserId(), e.getMessage());
            throw new RuntimeException("Failed to serialize Kafka event", e);
        }
    }
}
