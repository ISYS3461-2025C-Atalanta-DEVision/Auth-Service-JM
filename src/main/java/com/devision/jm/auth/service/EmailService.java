package com.devision.jm.auth.service;

import com.devision.jm.auth.model.entity.User;

/**
 * Email Service Interface
 *
 * Handles all email communications for the Auth Service.
 * Implements requirements:
 * - 1.1.3: Send activation email to new companies
 * - 6.1.2: Send subscription expiration notifications
 */
public interface EmailService {

    /**
     * Send account activation email (Requirement 1.1.3)
     *
     * @param user The registered user
     * @param activationToken The activation token
     */
    void sendActivationEmail(User user, String activationToken);

    /**
     * Send password reset email
     *
     * @param user The user requesting password reset
     * @param resetToken The password reset token
     */
    void sendPasswordResetEmail(User user, String resetToken);

    /**
     * Send password change confirmation email
     *
     * @param user The user who changed their password
     */
    void sendPasswordChangeConfirmation(User user);

    /**
     * Send welcome email after account activation
     *
     * @param user The activated user
     */
    void sendWelcomeEmail(User user);

    /**
     * Send subscription expiration warning (Requirement 6.1.2)
     * 7 days before expiration
     *
     * @param user The user with expiring subscription
     * @param daysRemaining Days until subscription expires
     */
    void sendSubscriptionExpirationWarning(User user, int daysRemaining);

    /**
     * Send subscription expired notification (Requirement 6.1.2)
     *
     * @param user The user with expired subscription
     */
    void sendSubscriptionExpiredNotification(User user);
}
