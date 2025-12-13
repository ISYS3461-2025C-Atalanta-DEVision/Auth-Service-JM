package com.devision.jm.auth.util;

import java.util.Set;

/**
 * Country Validator Utility
 *
 * Validates country input against a predefined list.
 * Implements requirement 1.24: Country must be selectable from dropdown.
 */
public final class CountryValidator {

    // Predefined list of valid countries (1.24)
    private static final Set<String> VALID_COUNTRIES = Set.of(
            // Southeast Asia
            "Vietnam",
            "Singapore",
            "Malaysia",
            "Thailand",
            "Indonesia",
            "Philippines",
            "Myanmar",
            "Cambodia",
            "Laos",
            "Brunei",
            // East Asia
            "China",
            "Japan",
            "South Korea",
            "Taiwan",
            "Hong Kong",
            // South Asia
            "India",
            "Bangladesh",
            "Pakistan",
            "Sri Lanka",
            // Oceania
            "Australia",
            "New Zealand",
            // Europe
            "United Kingdom",
            "Germany",
            "France",
            "Netherlands",
            "Sweden",
            "Norway",
            "Denmark",
            "Finland",
            "Switzerland",
            "Austria",
            "Belgium",
            "Ireland",
            "Spain",
            "Italy",
            "Portugal",
            "Poland",
            "Czech Republic",
            // North America
            "United States",
            "Canada",
            // South America
            "Brazil",
            "Argentina",
            "Chile",
            "Colombia",
            "Mexico",
            // Middle East
            "United Arab Emirates",
            "Saudi Arabia",
            "Israel",
            "Qatar",
            // Africa
            "South Africa",
            "Nigeria",
            "Egypt",
            "Kenya"
    );

    private CountryValidator() {
        // Utility class - prevent instantiation
    }

    /**
     * Check if country is valid
     *
     * @param country Country name to validate
     * @return true if country is in the predefined list
     */
    public static boolean isValidCountry(String country) {
        if (country == null || country.isBlank()) {
            return false;
        }
        return VALID_COUNTRIES.contains(country.trim());
    }

    /**
     * Get all valid countries (for dropdown population)
     *
     * @return Set of valid country names
     */
    public static Set<String> getValidCountries() {
        return Set.copyOf(VALID_COUNTRIES);
    }
}
