package com.devision.jm.auth.api.internal.interfaces;

import com.devision.jm.auth.model.entity.User;

/**
 * Email Service Interface (Internal API)
 *
 * Internal service for sending emails.
 * NOT accessible by other modules - only used within auth-core.
 *
 * Implements:
 * - 1.1.3: Account activation email
 * - Password reset/change emails
 * - 6.1.2: Subscription notifications
 */
public interface EmailService {

    /**
     * Send account activation email after registration
     */
    void sendActivationEmail(User user, String activationToken);

    /**
     * Send password reset email
     */
    void sendPasswordResetEmail(User user, String resetToken);

    /**
     * Send confirmation after password change
     */
    void sendPasswordChangeConfirmation(User user);

    /**
     * Send welcome email after activation
     */
    void sendWelcomeEmail(User user);

    /**
     * Send warning before subscription expires
     */
    void sendSubscriptionExpirationWarning(User user, int daysRemaining);

    /**
     * Send notification when subscription has expired
     */
    void sendSubscriptionExpiredNotification(User user);
}
