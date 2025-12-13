package com.devision.jm.auth.api.external.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Company Registration Request DTO (External)
 *
 * Used for company registration endpoint.
 * Accessible by external modules/services.
 *
 * Implements requirements:
 * - 1.1.1: Email, Password, Country (mandatory); Phone, Street, City (optional)
 * - 1.2.1: Password strength validation
 * - 1.2.2: Email syntax validation
 * - 1.2.3: Phone number validation
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompanyRegistrationRequest {

    /**
     * Email address (mandatory)
     *
     * Validation (1.2.2):
     * - Contains exactly one '@' symbol
     * - Contains at least one '.' after '@'
     * - Total length < 255 characters
     * - No spaces or prohibited characters
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    @Size(max = 254, message = "Email must be less than 255 characters")
    @Pattern(
            regexp = "^[^\\s()\\[\\];:]+@[^\\s@]+\\.[^\\s@]+$",
            message = "Email contains invalid characters"
    )
    private String email;

    /**
     * Password (mandatory)
     *
     * Validation (1.2.1):
     * - At least 8 characters
     * - At least 1 number
     * - At least 1 special character
     * - At least 1 capitalized letter
     */
    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(
            regexp = "^(?=.*[0-9])(?=.*[A-Z])(?=.*[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]).{8,}$",
            message = "Password must contain at least 1 number, 1 special character, and 1 uppercase letter"
    )
    private String password;

    /**
     * Country (mandatory)
     *
     * Requirement 1.24: Must be from a selectable dropdown list
     * Validation is done against a predefined list of countries
     */
    @NotBlank(message = "Country is required")
    @Size(max = 100, message = "Country must be less than 100 characters")
    private String country;

    /**
     * Company name (optional for registration, can be set later in profile)
     */
    @Size(max = 255, message = "Company name must be less than 255 characters")
    private String companyName;

    /**
     * Phone number (optional)
     *
     * Validation (1.2.3):
     * - Contains only digits
     * - Starts with valid international dial code
     * - Digits after dial code < 13
     */
    @Pattern(
            regexp = "^$|^\\+[1-9]\\d{0,2}\\d{1,12}$",
            message = "Phone number must start with a valid dial code (e.g., +84) followed by up to 12 digits"
    )
    private String phoneNumber;

    /**
     * Street address (optional)
     */
    @Size(max = 255, message = "Street address must be less than 255 characters")
    private String streetAddress;

    /**
     * City (optional)
     */
    @Size(max = 100, message = "City must be less than 100 characters")
    private String city;
}
