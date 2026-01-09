package com.devision.jm.auth.controller;

import com.devision.jm.auth.api.external.dto.AdminUserResponse;
import com.devision.jm.auth.api.external.interfaces.AdminAuthApi;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Admin Controller
 *
 * REST controller for admin/JA team endpoints.
 * Provides company management operations for external partners.
 *
 * Security: These endpoints require X-External-Api-Key header.
 * Configured in API Gateway's external endpoints list.
 *
 * Endpoints:
 * - POST   /api/admin/companies/{userId}/deactivate - Deactivate company (block access)
 * - POST   /api/admin/companies/{userId}/activate   - Reactivate company
 * - DELETE /api/admin/companies/{userId}            - Delete company (hard delete)
 */
@Slf4j
@RestController
@RequestMapping("/api/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminAuthApi adminService;

    /**
     * Deactivate a company (block user access)
     * POST /api/admin/companies/{userId}/deactivate
     *
     * Sets account status to DEACTIVATED.
     * User will not be able to login until reactivated.
     */
    @PostMapping("/companies/{userId}/deactivate")
    public ResponseEntity<AdminUserResponse> deactivateCompany(@PathVariable String userId) {
        log.info("Admin: Deactivating company userId: {}", userId);
        AdminUserResponse response = adminService.deactivateCompany(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Reactivate a company (unblock user access)
     * POST /api/admin/companies/{userId}/activate
     *
     * Sets account status back to ACTIVE.
     */
    @PostMapping("/companies/{userId}/activate")
    public ResponseEntity<AdminUserResponse> activateCompany(@PathVariable String userId) {
        log.info("Admin: Activating company userId: {}", userId);
        AdminUserResponse response = adminService.activateCompany(userId);
        return ResponseEntity.ok(response);
    }

    /**
     * Delete a company (hard delete)
     * DELETE /api/admin/companies/{userId}
     *
     * Permanently removes the company from the system.
     * This action cannot be undone.
     */
    @DeleteMapping("/companies/{userId}")
    public ResponseEntity<Void> deleteCompany(@PathVariable String userId) {
        log.info("Admin: Deleting company userId: {}", userId);
        adminService.deleteCompany(userId);
        return ResponseEntity.noContent().build();
    }
}
