package com.devision.jm.auth.model.entity;

import lombok.*;
import lombok.experimental.SuperBuilder;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.Field;

import java.time.LocalDateTime;

/**
 * Refresh Token Document (MongoDB)
 *
 * Stores refresh tokens for the token refresh mechanism (2.3.3).
 * Enables long-lived sessions without compromising access token security.
 */
@Document(collection = "refresh_tokens")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@SuperBuilder
public class RefreshToken extends BaseEntity {

    @Indexed(unique = true)
    @Field("token")
    private String token;

    @DBRef
    @Field("user")
    private User user;

    @Field("user_id")
    @Indexed
    private String userId;  // Denormalized for efficient queries

    @Field("expires_at")
    private LocalDateTime expiresAt;

    @Builder.Default
    @Field("revoked")
    private boolean revoked = false;

    @Field("revoked_at")
    private LocalDateTime revokedAt;

    @Field("replaced_by_token")
    private String replacedByToken;  // For token rotation

    @Field("device_info")
    private String deviceInfo;  // Optional: store device/browser info

    @Field("ip_address")
    private String ipAddress;

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Check if token is valid (not expired and not revoked)
     */
    public boolean isValid() {
        return !isExpired() && !revoked;
    }

    /**
     * Revoke this token
     */
    public void revoke() {
        this.revoked = true;
        this.revokedAt = LocalDateTime.now();
    }
}
