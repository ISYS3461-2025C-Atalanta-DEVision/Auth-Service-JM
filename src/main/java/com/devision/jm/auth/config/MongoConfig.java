package com.devision.jm.auth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.MongoDatabaseFactory;
import org.springframework.data.mongodb.MongoTransactionManager;

/**
 * MongoDB Configuration
 *
 * Configures MongoDB transaction support for @Transactional annotations.
 * Required for atomic operations across multiple document updates.
 *
 * Note: MongoDB transactions require a replica set. MongoDB Atlas M0 (free tier)
 * does support transactions as it runs on a replica set.
 */
@Configuration
public class MongoConfig {

    /**
     * MongoDB Transaction Manager
     *
     * Enables Spring's @Transactional annotation to work with MongoDB.
     * This is required for multi-document ACID transactions.
     */
    @Bean
    MongoTransactionManager transactionManager(MongoDatabaseFactory dbFactory) {
        return new MongoTransactionManager(dbFactory);
    }
}
