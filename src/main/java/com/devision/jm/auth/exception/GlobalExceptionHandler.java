package com.devision.jm.auth.exception;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global Exception Handler for Auth Service
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @Data
    @AllArgsConstructor
    public static class ErrorResponse {
        private String error;
        private String message;
        private String path;
        private LocalDateTime timestamp;
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(
            AuthException ex, HttpServletRequest request) {
        log.warn("Auth exception: {} - Path: {}", ex.getMessage(), request.getRequestURI());

        ErrorResponse response = new ErrorResponse(
                ex.getErrorCode(),
                ex.getMessage(),
                request.getRequestURI(),
                LocalDateTime.now()
        );
        return ResponseEntity.status(ex.getStatus()).body(response);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidationException(
            MethodArgumentNotValidException ex, HttpServletRequest request) {
        Map<String, String> fieldErrors = new HashMap<>();

        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            fieldErrors.put(fieldName, errorMessage);
        });

        log.warn("Validation failed for {}: {}", request.getRequestURI(), fieldErrors);

        Map<String, Object> response = new HashMap<>();
        response.put("error", "VALIDATION_FAILED");
        response.put("message", "Validation failed");
        response.put("errors", fieldErrors);
        response.put("path", request.getRequestURI());
        response.put("timestamp", LocalDateTime.now());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
            Exception ex, HttpServletRequest request) {
        log.error("Unexpected error at {}: ", request.getRequestURI(), ex);

        ErrorResponse response = new ErrorResponse(
                "INTERNAL_ERROR",
                "An unexpected error occurred",
                request.getRequestURI(),
                LocalDateTime.now()
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}
