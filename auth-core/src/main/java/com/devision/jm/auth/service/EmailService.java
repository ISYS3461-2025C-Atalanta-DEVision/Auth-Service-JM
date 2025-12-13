package com.devision.jm.auth.service;

import com.devision.jm.auth.model.entity.User;

/**
 * Email Service Interface
 *
 * Internal service for sending emails.
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
