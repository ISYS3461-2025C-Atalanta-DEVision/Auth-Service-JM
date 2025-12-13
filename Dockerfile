# Multi-module Dockerfile for Render Deployment
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /app

# Install Maven
RUN apt-get update && apt-get install -y maven && rm -rf /var/lib/apt/lists/*

# Copy all pom.xml files first (for dependency caching)
COPY pom.xml ./pom.xml
COPY auth-api/pom.xml ./auth-api/pom.xml
COPY auth-core/pom.xml ./auth-core/pom.xml
COPY auth-app/pom.xml ./auth-app/pom.xml

# Create source directories
RUN mkdir -p auth-api/src auth-core/src auth-app/src

# Download dependencies (cached layer)
RUN mvn dependency:go-offline -B || true

# Copy source code for all modules
COPY auth-api/src ./auth-api/src
COPY auth-core/src ./auth-core/src
COPY auth-app/src ./auth-app/src

# Build all modules (auth-app depends on auth-api and auth-core)
RUN mvn clean package -DskipTests -B -pl auth-app -am

# Runtime image
FROM eclipse-temurin:21-jre

WORKDIR /app

# Add curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

# Copy the built jar from auth-app module
COPY --from=builder /app/auth-app/target/*.jar app.jar

# Set ownership
RUN chown -R appuser:appgroup /app

# Switch to non-root user
USER appuser

# Expose port (Render will override with PORT env var)
EXPOSE 8081

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:${PORT:-8081}/actuator/health || exit 1

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
