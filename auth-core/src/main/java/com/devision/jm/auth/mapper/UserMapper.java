package com.devision.jm.auth.mapper;

import com.devision.jm.auth.api.internal.dto.UserInternalDto;
import com.devision.jm.auth.model.entity.User;
import org.mapstruct.*;

/**
 * User Mapper
 *
 * MapStruct mapper for converting between:
 * - Entity (User)
 * - Internal DTO (UserInternalDto)
 *
 * Microservice Architecture (A.3.1):
 * - Auth Service owns: email, password, tokens, security fields
 * - Profile Service owns: company info, contact info (via Kafka)
 *
 * Implements A.2.6: DTO organization into internal and external.
 *
 * NOTE: CompanyProfileResponse mappings removed - profile is now handled by Profile Service
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
}
