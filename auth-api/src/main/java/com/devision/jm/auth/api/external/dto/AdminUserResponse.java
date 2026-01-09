package com.devision.jm.auth.api.external.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Admin User Response DTO
 *
 * Response DTO for admin operations on company accounts.
 * Used by JA team for company management.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminUserResponse {

    private String userId;
    private String email;
    private String status;
    private String message;
}
