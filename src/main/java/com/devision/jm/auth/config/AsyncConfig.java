package com.devision.jm.auth.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Async Configuration
 *
 * Enables asynchronous processing for email sending.
 * This ensures that email operations don't block the main request thread.
 */
@Configuration
@EnableAsync
public class AsyncConfig {
    // Default Spring async executor is used
    // For production, consider configuring a custom ThreadPoolTaskExecutor
}
