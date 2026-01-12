package com.devision.jm.auth.api.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * User Deleted Event (Internal DTO)
 *
 * Kafka event published when a user/company is deleted by admin.
 * Profile Service and other services consume this event to clean up related data.
 *
 * Microservice Architecture (A.3.2):
 * - Communication among microservices via Message Broker (Kafka)
 *
 * Topic: user-deleted
 *
 * Consuming Services:
 * - Profile Service: Deletes profile and events
 * - File Service: Deletes S3 files (avatars, event media)
 * - Other services: Clean up user-related data
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDeletedEvent {

    /**
     * User ID from Auth Service (MongoDB ObjectId as String)
     * This is the reference key used by other services
     */
    private String userId;

    /**
     * User's email - for audit/logging purposes
     */
    private String email;

    /**
     * Reason for deletion (optional)
     */
    private String reason;

    /**
     * Admin who performed the deletion (optional)
     */
    private String deletedBy;

    /**
     * Event timestamp
     */
    private LocalDateTime deletedAt;
}
