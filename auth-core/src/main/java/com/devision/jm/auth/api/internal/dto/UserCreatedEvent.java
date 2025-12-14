package com.devision.jm.auth.api.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * User Created Event (Internal DTO)
 *
 * Kafka event published when a new user registers.
 * Profile Service consumes this event to create the user's profile.
 *
 * Microservice Architecture (A.3.2):
 * - Communication among microservices via Message Broker (Kafka)
 *
 * Topic: user-created
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserCreatedEvent {

    /**
     * User ID from Auth Service (MongoDB ObjectId as String)
     * This becomes the reference key in Profile Service
     */
    private String userId;

    /**
     * User's email - copied to Profile for display purposes
     */
    private String email;

    /**
     * Company name from registration
     */
    private String companyName;

    /**
     * Country (mandatory field from registration)
     * Used for sharding in Profile Service (1.3.3)
     */
    private String country;

    /**
     * City (optional)
     */
    private String city;

    /**
     * Street address (optional)
     */
    private String streetAddress;

    /**
     * Phone number (optional)
     */
    private String phoneNumber;

    /**
     * Avatar URL (from Google OAuth profile picture)
     */
    private String avatarUrl;

    /**
     * Auth provider (LOCAL, GOOGLE, etc.)
     * Profile Service may need this for display
     */
    private String authProvider;

    /**
     * Event timestamp
     */
    private LocalDateTime createdAt;
}
