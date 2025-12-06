package com.devision.jm.auth.config;

import com.devision.jm.auth.event.KafkaTopics;
import org.apache.kafka.clients.admin.NewTopic;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.TopicBuilder;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka Configuration
 *
 * Configures Kafka for inter-service communication (A.3.2).
 *
 * Event Flow:
 * ┌─────────────────────────────────────────────────────────────────────────────┐
 * │                           KAFKA TOPICS                                      │
 * │                                                                             │
 * │  ┌─────────────────┐                                                        │
 * │  │  USER_EVENTS    │ ──► Profile Service (create profile)                   │
 * │  │                 │ ──► Notification Service (welcome email)               │
 * │  └─────────────────┘                                                        │
 * │                                                                             │
 * │  ┌─────────────────┐                                                        │
 * │  │  AUTH_EVENTS    │ ──► Profile Service (update last login)                │
 * │  │                 │ ──► Audit Service (log activities)                     │
 * │  └─────────────────┘                                                        │
 * │                                                                             │
 * │  ┌─────────────────┐                                                        │
 * │  │ NOTIFICATION_   │ ──► Notification Service (send emails/SMS)             │
 * │  │    EVENTS       │                                                        │
 * │  └─────────────────┘                                                        │
 * └─────────────────────────────────────────────────────────────────────────────┘
 */
@Configuration
public class KafkaConfig {

    @Value("${spring.kafka.bootstrap-servers:localhost:9092}")
    private String bootstrapServers;

    @Bean
    public ProducerFactory<String, String> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        // Reliability settings
        configProps.put(ProducerConfig.ACKS_CONFIG, "all");
        configProps.put(ProducerConfig.RETRIES_CONFIG, 3);
        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);

        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public KafkaTemplate<String, String> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }

    // ==================== TOPIC DEFINITIONS ====================

    /**
     * User events topic - user lifecycle events
     * Consumers: Profile Service, Notification Service
     */
    @Bean
    public NewTopic userEventsTopic() {
        return TopicBuilder.name(KafkaTopics.USER_EVENTS)
                .partitions(3)
                .replicas(1)
                .build();
    }

    /**
     * Auth events topic - authentication events
     * Consumers: Profile Service (last login), Audit Service
     */
    @Bean
    public NewTopic authEventsTopic() {
        return TopicBuilder.name(KafkaTopics.AUTH_EVENTS)
                .partitions(3)
                .replicas(1)
                .build();
    }

    /**
     * Notification events topic - triggers emails/SMS/push
     * Consumers: Notification Service
     */
    @Bean
    public NewTopic notificationEventsTopic() {
        return TopicBuilder.name(KafkaTopics.NOTIFICATION_EVENTS)
                .partitions(3)
                .replicas(1)
                .build();
    }
}
