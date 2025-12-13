package com.devision.jm.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.MongoDatabaseFactory;
import org.springframework.data.mongodb.MongoTransactionManager;

/**
 * MongoDB Configuration
 *
 * Configures MongoDB transaction support for @Transactional annotations.
 * Required for atomic operations across multiple document updates (A.3.5 Bonus).
 *
 * Note: MongoDB transactions require a replica set. MongoDB Atlas M0 (free tier)
 * runs on a shared replica set which may have transaction limitations.
 */
@Slf4j
@Configuration
public class MongoConfig {

    /**
     * MongoDB Transaction Manager
     *
     * Enables Spring's @Transactional annotation to work with MongoDB.
     * This is required for multi-document ACID transactions (A.3.5 Bonus Feature).
     *
     * If transactions fail on MongoDB Atlas free tier, individual operations
     * are still atomic at the document level.
     */
    @Bean
    MongoTransactionManager transactionManager(MongoDatabaseFactory dbFactory) {
        log.info("Configuring MongoDB Transaction Manager for ACID transactions (A.3.5)");
        return new MongoTransactionManager(dbFactory);
    }
}
