package com.devision.jm.auth.mapper;

import com.devision.jm.auth.api.external.dto.CompanyProfileResponse;
import com.devision.jm.auth.api.external.dto.CompanyRegistrationRequest;
import com.devision.jm.auth.api.internal.dto.UserInternalDto;
import com.devision.jm.auth.model.entity.User;
import org.mapstruct.*;

/**
 * User Mapper
 *
 * MapStruct mapper for converting between:
 * - Entity (User)
 * - Internal DTO (UserInternalDto)
 * - External DTOs (CompanyRegistrationRequest, CompanyProfileResponse)
 *
 * Implements A.2.6: DTO organization into internal and external.
 */
@Mapper(componentModel = "spring", unmappedTargetPolicy = ReportingPolicy.IGNORE)
public interface UserMapper {

    // ==================== Entity <-> Internal DTO ====================

    /**
     * Convert User entity to Internal DTO
     */
    UserInternalDto toInternalDto(User user);

    /**
     * Convert Internal DTO to User entity
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    User toEntity(UserInternalDto dto);

    /**
     * Update entity from Internal DTO
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    void updateEntityFromInternalDto(UserInternalDto dto, @MappingTarget User user);

    // ==================== Registration Request -> Entity ====================

    /**
     * Convert Registration Request to User entity
     * Note: Password hash, role, status, etc. are set in service layer
     */
    @Mapping(target = "id", ignore = true)
    @Mapping(target = "passwordHash", ignore = true)
    @Mapping(target = "role", ignore = true)
    @Mapping(target = "status", ignore = true)
    @Mapping(target = "authProvider", ignore = true)
    @Mapping(target = "providerId", ignore = true)
    @Mapping(target = "failedLoginAttempts", ignore = true)
    @Mapping(target = "lastFailedLogin", ignore = true)
    @Mapping(target = "lockedUntil", ignore = true)
    @Mapping(target = "activationToken", ignore = true)
    @Mapping(target = "activationTokenExpiry", ignore = true)
    @Mapping(target = "lastPasswordChange", ignore = true)
    @Mapping(target = "lastLogin", ignore = true)
    @Mapping(target = "createdAt", ignore = true)
    @Mapping(target = "updatedAt", ignore = true)
    @Mapping(target = "version", ignore = true)
    User registrationRequestToEntity(CompanyRegistrationRequest request);

    // ==================== Entity -> External DTO ====================

    /**
     * Convert User entity to Company Profile Response
     * Implements A.2.5: Only necessary data exposed
     */
    @Mapping(target = "id", expression = "java(user.getId() != null ? user.getId().toString() : null)")
    @Mapping(target = "status", expression = "java(user.getStatus() != null ? user.getStatus().name() : null)")
    CompanyProfileResponse toCompanyProfileResponse(User user);

    /**
     * Convert Internal DTO to Company Profile Response
     */
    @Mapping(target = "id", expression = "java(dto.getId() != null ? dto.getId().toString() : null)")
    @Mapping(target = "status", expression = "java(dto.getStatus() != null ? dto.getStatus().name() : null)")
    CompanyProfileResponse internalDtoToCompanyProfileResponse(UserInternalDto dto);
}
