package com.devision.jm.auth.service.impl;

import com.devision.jm.auth.model.entity.User;
import com.devision.jm.auth.service.EmailService;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/**
 * Email Service Implementation using SMTP (Brevo/SendGrid)
 *
 * FLOW OVERVIEW:
 * 1. Service method called (e.g., sendActivationEmail) with User object and token
 * 2. Method builds the activation/reset link using frontendUrl + token
 * 3. HTML email template is generated with user-specific data
 * 4. sendHtmlEmail() creates a MIME message and sends via SMTP
 * 5. All methods are @Async - they run in background thread, don't block caller
 *
 * Implements Requirements:
 * - 1.1.3: Account activation email with activation link
 * - Password reset email flow
 * - 6.1.2: Subscription expiration notifications
 */
@Slf4j      // Lombok: auto-generates private static final Logger log = LoggerFactory.getLogger(...)
@Service    // Spring: marks this as a service bean, auto-registered in application context
@RequiredArgsConstructor  // Lombok: generates constructor for final fields (mailSender injection)
public class EmailServiceImpl implements EmailService {

    // Spring's mail sender - configured via application.yml (spring.mail.*)
    // Injected automatically via constructor (RequiredArgsConstructor)
    private final JavaMailSender mailSender;

    // Frontend URL for building activation/reset links
    // Configured via APP_FRONTEND_URL env variable on Render
    @Value("${app.frontend-url}")
    private String frontendUrl;

    // Sender email address shown in "From" field
    // Configured via APP_FROM_EMAIL env variable on Render
    @Value("${app.from-email}")
    private String fromEmail;

    // Application name used in email subjects and body
    // Configured via APP_NAME env variable on Render
    @Value("${app.name}")
    private String appName;

    // ==================== ACCOUNT ACTIVATION EMAIL (Requirement 1.1.3) ====================

    /**
     * Sends account activation email after company registration.
     *
     * @param user            The newly registered user
     * @param activationToken Unique token for account activation (stored in DB)
     *
     * Flow:
     * 1. User registers → AuthService generates activationToken → calls this method
     * 2. This method builds link: https://frontend.com/activate?token=abc123
     * 3. User clicks link → Frontend calls POST /api/auth/activate?token=abc123
     * 4. Backend validates token → Activates account → Status changes to ACTIVE
     */
    @Override
    @Async  // Runs in separate thread - registration response returns immediately
    public void sendActivationEmail(User user, String activationToken) {
        // Build the activation link that user will click in the email
        // Example: https://devision-jm.com/activate?token=abc123-def456-ghi789
        String activationLink = frontendUrl + "/activate?token=" + activationToken;

        // Email subject line
        String subject = "Activate Your " + appName + " Account";

        // Generate HTML email body using template method
        String htmlContent = buildActivationEmailHtml(user, activationLink);

        // Send the email via SMTP
        sendHtmlEmail(user.getEmail(), subject, htmlContent);

        // Log success for monitoring/debugging
        log.info("Activation email sent to: {}", user.getEmail());
    }

    // ==================== PASSWORD RESET EMAIL ====================

    /**
     * Sends password reset email when user requests password recovery.
     *
     * @param user       The user requesting password reset
     * @param resetToken Unique token for password reset (expires in 1 hour)
     *
     * Flow:
     * 1. User clicks "Forgot Password" → enters email
     * 2. Backend generates resetToken → stores in DB with expiry → calls this method
     * 3. User receives email → clicks link → Frontend shows new password form
     * 4. User submits new password → Backend validates token → Updates password
     */
    @Override
    @Async  // Non-blocking - response returns immediately to user
    public void sendPasswordResetEmail(User user, String resetToken) {
        // Build reset link: https://frontend.com/reset-password?token=xyz789
        String resetLink = frontendUrl + "/reset-password?token=" + resetToken;

        String subject = "Reset Your " + appName + " Password";

        String htmlContent = buildPasswordResetEmailHtml(user, resetLink);

        sendHtmlEmail(user.getEmail(), subject, htmlContent);
        log.info("Password reset email sent to: {}", user.getEmail());
    }

    // ==================== PASSWORD CHANGE CONFIRMATION ====================

    /**
     * Sends confirmation email after successful password change.
     * Security feature: notifies user in case of unauthorized password change.
     *
     * @param user The user whose password was changed
     */
    @Override
    @Async
    public void sendPasswordChangeConfirmation(User user) {
        String subject = "Your " + appName + " Password Has Been Changed";

        String htmlContent = buildPasswordChangeConfirmationHtml(user);

        sendHtmlEmail(user.getEmail(), subject, htmlContent);
        log.info("Password change confirmation email sent to: {}", user.getEmail());
    }

    // ==================== WELCOME EMAIL (After Activation) ====================

    /**
     * Sends welcome email after account is successfully activated.
     *
     * @param user The newly activated user
     */
    @Override
    @Async
    public void sendWelcomeEmail(User user) {
        String subject = "Welcome to " + appName + "!";

        String htmlContent = buildWelcomeEmailHtml(user);

        sendHtmlEmail(user.getEmail(), subject, htmlContent);
        log.info("Welcome email sent to: {}", user.getEmail());
    }

    // ==================== SUBSCRIPTION NOTIFICATIONS (Requirement 6.1.2) ====================

    /**
     * Sends warning email when subscription is about to expire.
     * Triggered by scheduled job that checks subscription dates.
     *
     * @param user          The user with expiring subscription
     * @param daysRemaining Number of days until subscription expires
     */
    @Override
    @Async
    public void sendSubscriptionExpirationWarning(User user, int daysRemaining) {
        String subject = "Your " + appName + " Subscription Expires in " + daysRemaining + " Days";

        String htmlContent = buildSubscriptionWarningHtml(user, daysRemaining);

        sendHtmlEmail(user.getEmail(), subject, htmlContent);
        log.info("Subscription warning email sent to: {} ({} days remaining)", user.getEmail(), daysRemaining);
    }

    /**
     * Sends notification when subscription has expired.
     * Account moves to read-only mode after this.
     *
     * @param user The user whose subscription expired
     */
    @Override
    @Async
    public void sendSubscriptionExpiredNotification(User user) {
        String subject = "Your " + appName + " Subscription Has Expired";

        String htmlContent = buildSubscriptionExpiredHtml(user);

        sendHtmlEmail(user.getEmail(), subject, htmlContent);
        log.info("Subscription expired email sent to: {}", user.getEmail());
    }

    // ==================== PRIVATE HELPER: SMTP EMAIL SENDER ====================

    /**
     * Core method that actually sends the email via SMTP.
     * All public methods delegate to this method.
     *
     * @param to          Recipient email address
     * @param subject     Email subject line
     * @param htmlContent HTML body of the email
     *
     * Uses JavaMailSender configured in application.yml:
     * - spring.mail.host: SMTP server (e.g., smtp-relay.brevo.com)
     * - spring.mail.port: SMTP port (587 for TLS)
     * - spring.mail.username: SMTP username
     * - spring.mail.password: SMTP password/API key
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent) {
        try {
            // Create a MIME message (supports HTML, attachments, etc.)
            MimeMessage message = mailSender.createMimeMessage();

            // MimeMessageHelper simplifies setting email properties
            // Parameters: message, multipart=true (for HTML), encoding=UTF-8
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            // Set email headers
            helper.setFrom(fromEmail);      // From: noreply@devision-jm.com
            helper.setTo(to);               // To: user@example.com
            helper.setSubject(subject);     // Subject: Activate Your Account

            // Set HTML body - second param 'true' indicates HTML content
            helper.setText(htmlContent, true);

            // Send via configured SMTP server
            mailSender.send(message);

        } catch (MessagingException e) {
            // Log error with recipient for debugging
            log.error("Failed to send email to {}: {}", to, e.getMessage());

            // Rethrow as RuntimeException - @Async methods handle exceptions separately
            throw new RuntimeException("Failed to send email", e);
        }
    }

    // ==================== Email Templates ====================

    private String buildActivationEmailHtml(User user, String activationLink) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>%s</h1>
                    </div>
                    <div class="content">
                        <h2>Welcome, %s!</h2>
                        <p>Thank you for registering your company with %s.</p>
                        <p>To complete your registration and activate your account, please click the button below:</p>
                        <p style="text-align: center;">
                            <a href="%s" class="button">Activate My Account</a>
                        </p>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; color: #4F46E5;">%s</p>
                        <p><strong>This activation link will expire in 24 hours.</strong></p>
                        <p>If you did not create this account, please ignore this email.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(appName, user.getCompanyName(), appName, activationLink, activationLink, appName);
    }

    private String buildPasswordResetEmailHtml(User user, String resetLink) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                    .warning { color: #dc2626; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>%s</h1>
                    </div>
                    <div class="content">
                        <h2>Password Reset Request</h2>
                        <p>Hello %s,</p>
                        <p>We received a request to reset your password. Click the button below to create a new password:</p>
                        <p style="text-align: center;">
                            <a href="%s" class="button">Reset Password</a>
                        </p>
                        <p>Or copy and paste this link into your browser:</p>
                        <p style="word-break: break-all; color: #4F46E5;">%s</p>
                        <p><strong>This link will expire in 1 hour.</strong></p>
                        <p class="warning">If you did not request this password reset, please ignore this email or contact support if you have concerns.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(appName, user.getCompanyName(), resetLink, resetLink, appName);
    }

    private String buildPasswordChangeConfirmationHtml(User user) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                    .warning { color: #dc2626; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>%s</h1>
                    </div>
                    <div class="content">
                        <h2>Password Changed Successfully</h2>
                        <p>Hello %s,</p>
                        <p>Your password has been changed successfully.</p>
                        <p>If you did not make this change, please contact our support team immediately.</p>
                        <p class="warning">For security reasons, you may need to log in again on your devices.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(appName, user.getCompanyName(), appName);
    }

    private String buildWelcomeEmailHtml(User user) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #4F46E5; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Welcome to %s!</h1>
                    </div>
                    <div class="content">
                        <h2>Account Activated Successfully</h2>
                        <p>Hello %s,</p>
                        <p>Congratulations! Your account has been activated and you're ready to start using %s.</p>
                        <p>Here's what you can do next:</p>
                        <ul>
                            <li>Complete your company profile</li>
                            <li>Post your first job listing</li>
                            <li>Explore our candidate matching features</li>
                        </ul>
                        <p style="text-align: center;">
                            <a href="%s/login" class="button">Login Now</a>
                        </p>
                        <p>If you have any questions, our support team is here to help.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(appName, user.getCompanyName(), appName, frontendUrl, appName);
    }

    private String buildSubscriptionWarningHtml(User user, int daysRemaining) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #f59e0b; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                    .highlight { font-size: 24px; color: #f59e0b; font-weight: bold; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Subscription Expiring Soon</h1>
                    </div>
                    <div class="content">
                        <h2>Hello %s,</h2>
                        <p>Your %s subscription will expire in:</p>
                        <p class="highlight" style="text-align: center;">%d Days</p>
                        <p>To avoid any interruption to your services, please renew your subscription before it expires.</p>
                        <p>After expiration, you will lose access to:</p>
                        <ul>
                            <li>Job posting features</li>
                            <li>Candidate matching</li>
                            <li>Analytics dashboard</li>
                        </ul>
                        <p style="text-align: center;">
                            <a href="%s/subscription" class="button">Renew Now</a>
                        </p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(user.getCompanyName(), appName, daysRemaining, frontendUrl, appName);
    }

    private String buildSubscriptionExpiredHtml(User user) {
        return """
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                    .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                    .header { background-color: #dc2626; color: white; padding: 20px; text-align: center; }
                    .content { padding: 20px; background-color: #f9f9f9; }
                    .button { display: inline-block; padding: 12px 24px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px; margin: 20px 0; }
                    .footer { padding: 20px; text-align: center; font-size: 12px; color: #666; }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>Subscription Expired</h1>
                    </div>
                    <div class="content">
                        <h2>Hello %s,</h2>
                        <p>Your %s subscription has officially expired.</p>
                        <p>Your account is now in read-only mode. To regain full access to all features, please renew your subscription.</p>
                        <p>Your data is safe and will be available once you reactivate your subscription.</p>
                        <p style="text-align: center;">
                            <a href="%s/subscription" class="button">Renew Subscription</a>
                        </p>
                        <p>If you have any questions or need assistance, please contact our support team.</p>
                    </div>
                    <div class="footer">
                        <p>&copy; 2024 %s. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """.formatted(user.getCompanyName(), appName, frontendUrl, appName);
    }
}
