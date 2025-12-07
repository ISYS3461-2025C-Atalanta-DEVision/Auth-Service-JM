package com.devision.jm.auth.api.internal.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Token Internal DTO
 *
 * Internal representation of token data.
 * Used within the auth service for token operations.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TokenInternalDto {

    private String accessToken;
    private String refreshToken;
    private LocalDateTime accessTokenExpiry;
    private LocalDateTime refreshTokenExpiry;
    private String userId;
    private String userEmail;
    private String role;
}
