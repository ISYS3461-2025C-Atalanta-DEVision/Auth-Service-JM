package com.devision.jm.auth.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.kafka.clients.CommonClientConfigs;
import org.apache.kafka.clients.producer.ProducerConfig;
import org.apache.kafka.common.config.SaslConfigs;
import org.apache.kafka.common.serialization.StringSerializer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.kafka.core.DefaultKafkaProducerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.kafka.core.ProducerFactory;

import java.util.HashMap;
import java.util.Map;

/**
 * Kafka Configuration
 *
 * Configures Kafka producer for publishing events to other microservices.
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
@ConditionalOnProperty(name = "kafka.enabled", havingValue = "true", matchIfMissing = true)
public class KafkaConfig {

    private final KafkaDiscoveryService kafkaDiscoveryService;

    // SASL/SSL authentication for Confluent Cloud
    @Value("${KAFKA_SECURITY_PROTOCOL:#{null}}")
    private String securityProtocol;

    @Value("${KAFKA_SASL_MECHANISM:#{null}}")
    private String saslMechanism;

    @Value("${KAFKA_SASL_USERNAME:#{null}}")
    private String saslUsername;

    @Value("${KAFKA_SASL_PASSWORD:#{null}}")
    private String saslPassword;

    @Bean
    public ProducerFactory<String, String> producerFactory() {
        Map<String, Object> configProps = new HashMap<>();

        // Get Kafka address from Eureka discovery
        String bootstrapServers = kafkaDiscoveryService.getKafkaBootstrapServers();
        log.info("Configuring Kafka Producer with bootstrap servers: {}", bootstrapServers);

        // Kafka broker addresses (discovered from Eureka)
        configProps.put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, bootstrapServers);

        // Key and value serializers
        configProps.put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer.class);
        configProps.put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer.class);

        // Reliability settings
        configProps.put(ProducerConfig.ACKS_CONFIG, "all");  // Wait for all replicas
        configProps.put(ProducerConfig.RETRIES_CONFIG, 3);   // Retry on failure
        configProps.put(ProducerConfig.ENABLE_IDEMPOTENCE_CONFIG, true);  // Exactly-once semantics

        // SASL/SSL authentication for Confluent Cloud
        if (securityProtocol != null && saslUsername != null && saslPassword != null) {
            log.info("Configuring SASL/SSL authentication for Kafka Producer");
            configProps.put(CommonClientConfigs.SECURITY_PROTOCOL_CONFIG, securityProtocol);
            configProps.put(SaslConfigs.SASL_MECHANISM, saslMechanism != null ? saslMechanism : "PLAIN");
            String jaasConfig = String.format(
                "org.apache.kafka.common.security.plain.PlainLoginModule required username=\"%s\" password=\"%s\";",
                saslUsername, saslPassword);
            configProps.put(SaslConfigs.SASL_JAAS_CONFIG, jaasConfig);
        }

        return new DefaultKafkaProducerFactory<>(configProps);
    }

    @Bean
    public KafkaTemplate<String, String> kafkaTemplate() {
        return new KafkaTemplate<>(producerFactory());
    }
}
