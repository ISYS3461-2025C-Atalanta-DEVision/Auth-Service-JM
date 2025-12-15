package com.devision.jm.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.client.discovery.DiscoveryClient;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.Map;

/**
 * Kafka Discovery Service
 *
 * Discovers Kafka broker address from Eureka via kafka-registrar service metadata.
 * This enables dynamic Kafka discovery instead of hardcoding the address.
 *
 * How it works:
 * 1. kafka-registrar registers with Eureka with metadata: kafkaBroker=kafka:9092
 * 2. This service queries Eureka for kafka-registrar
 * 3. Reads the kafkaBroker from metadata
 * 4. Falls back to config value if discovery fails
 */
@Slf4j
@Component
public class KafkaDiscoveryService {

    private static final String KAFKA_REGISTRAR_SERVICE = "kafka-registrar";
    private static final String KAFKA_BROKER_METADATA_KEY = "kafkaBroker";

    private final DiscoveryClient discoveryClient;
    private final String fallbackBootstrapServers;

    private String kafkaBootstrapServers;

    public KafkaDiscoveryService(
            DiscoveryClient discoveryClient,
            @Value("${spring.kafka.bootstrap-servers:localhost:9092}") String fallbackBootstrapServers) {
        this.discoveryClient = discoveryClient;
        this.fallbackBootstrapServers = fallbackBootstrapServers;
    }

    @PostConstruct
    public void init() {
        discoverKafka();
    }

    /**
     * Discover Kafka broker address from Eureka
     */
    public void discoverKafka() {
        try {
            List<ServiceInstance> instances = discoveryClient.getInstances(KAFKA_REGISTRAR_SERVICE);

            if (instances.isEmpty()) {
                log.warn("kafka-registrar not found in Eureka, using fallback: {}", fallbackBootstrapServers);
                kafkaBootstrapServers = fallbackBootstrapServers;
                return;
            }

            // Read the kafkaBroker from metadata
            ServiceInstance instance = instances.get(0);
            Map<String, String> metadata = instance.getMetadata();

            String discoveredBroker = metadata.get(KAFKA_BROKER_METADATA_KEY);

            if (discoveredBroker != null && !discoveredBroker.isEmpty()) {
                kafkaBootstrapServers = discoveredBroker;
                log.info("========== KAFKA DISCOVERED VIA EUREKA ==========");
                log.info("Service: {}", KAFKA_REGISTRAR_SERVICE);
                log.info("Kafka Bootstrap Servers: {}", kafkaBootstrapServers);
                log.info("=================================================");
            } else {
                log.warn("kafkaBroker metadata not found, using fallback: {}", fallbackBootstrapServers);
                kafkaBootstrapServers = fallbackBootstrapServers;
            }

        } catch (Exception e) {
            log.error("Failed to discover Kafka from Eureka: {}. Using fallback: {}",
                    e.getMessage(), fallbackBootstrapServers);
            kafkaBootstrapServers = fallbackBootstrapServers;
        }
    }

    /**
     * Get the discovered Kafka bootstrap servers
     */
    public String getKafkaBootstrapServers() {
        if (kafkaBootstrapServers == null) {
            discoverKafka();
        }
        return kafkaBootstrapServers;
    }

    /**
     * Refresh the Kafka address from Eureka (can be called periodically)
     */
    public void refresh() {
        log.info("Refreshing Kafka discovery from Eureka...");
        discoverKafka();
    }
}
