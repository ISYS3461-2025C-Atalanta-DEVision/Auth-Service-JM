package com.devision.jm.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.consumer.ConsumerConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.serialization.StringDeserializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.config.ConcurrentKafkaListenerContainerFactory;
import org.springframework.kafka.core.ConsumerFactory;
import org.springframework.kafka.core.DefaultKafkaConsumerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka Consumer Configuration
 *
 * Configures Kafka consumer for receiving events from other microservices.
 * Discovers Kafka address from Eureka via KafkaDiscoveryService.
 *
 * Implements Microservice Architecture (A.3.2):
 * - Communication among microservices via Message Broker (Kafka)
 *
 * Discovery Flow:
 * 1. KafkaDiscoveryService queries Eureka for kafka-registrar
 * 2. Reads kafkaBroker from metadata
 * 3. Falls back to application.yml if discovery fails
 */
@Slf4j
@Configuration
@RequiredArgsConstructor
@ConditionalOnProperty(name = "kafka.enabled", havingValue = "true")
public class KafkaConsumerConfig {

    private final KafkaDiscoveryService kafkaDiscoveryService;

    @Value("${spring.kafka.consumer.group-id:auth-service-group}")
    private String groupId;

    // SASL/SSL authentication for Confluent Cloud
    @Value("${KAFKA_SECURITY_PROTOCOL:#{null}}")
    private String securityProtocol;

    @Value("${KAFKA_SASL_MECHANISM:#{null}}")
    private String saslMechanism;

    @Value("${KAFKA_SASL_USERNAME:#{null}}")
    private String saslUsername;

    @Value("${KAFKA_SASL_PASSWORD:#{null}}")
    private String saslPassword;

    /**
     * Add SASL/SSL configuration for Confluent Cloud
     */
    private void addSaslConfig(Map<String, Object> configProps) {
        if (securityProtocol != null && saslUsername != null && saslPassword != null) {
            log.info("Configuring SASL/SSL authentication for Kafka Consumer");
            configProps.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, securityProtocol);
            configProps.put(SaslConfigs.SASL_MECHANISM, saslMechanism != null ? saslMechanism : "PLAIN");
            String jaasConfig = String.format(
                "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"%s\" password=\"%s\";",
                saslUsername, saslPassword);
            configProps.put(SaslConfigs.SASL_JAAS_CONFIG, jaasConfig);
        }
    }

    /**
     * Consumer factory for String messages
     * Used by SubscriptionNotificationConsumer
     */
    @Bean
    public ConsumerFactory<String, String> consumerFactory() {
        Map<String, Object> props = new HashMap<>();

        // Get Kafka address from Eureka discovery
        String bootstrapServers = kafkaDiscoveryService.getKafkaBootstrapServers();
        log.info("Configuring Kafka Consumer with bootstrap servers: {}", bootstrapServers);

        props.put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);
        props.put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer.class);
        props.put(ConsumerConfig.GROUP_ID_CONFIG, groupId);
        props.put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest");

        // Add SASL/SSL for Confluent Cloud
        addSaslConfig(props);

        return new DefaultKafkaConsumerFactory<>(props);
    }

    /**
     * Kafka listener container factory
     * Used by @KafkaListener annotations
     */
    @Bean
    public ConcurrentKafkaListenerContainerFactory<String, String> kafkaListenerContainerFactory() {
        ConcurrentKafkaListenerContainerFactory<String, String> factory = new ConcurrentKafkaListenerContainerFactory<>();
        factory.setConsumerFactory(consumerFactory());
        return factory;
    }
}
