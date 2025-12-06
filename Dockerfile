# Auth Service Dockerfile
FROM eclipse-temurin:21-jdk AS builder

WORKDIR /app

# Copy parent pom and ALL module poms (required for multi-module build)
COPY pom.xml ./pom.xml
COPY eureka-server/pom.xml ./eureka-server/pom.xml
COPY api-gateway/pom.xml ./api-gateway/pom.xml
COPY auth-service/pom.xml ./auth-service/pom.xml

# Copy only this module's source
COPY auth-service/src ./auth-service/src

# Build the application
RUN apt-get update && apt-get install -y maven && \
    mvn clean package -DskipTests -pl auth-service -am

# Runtime image
FROM eclipse-temurin:21-jre

WORKDIR /app

# Add curl for health checks
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# Copy the built jar
COPY --from=builder /app/auth-service/target/*.jar app.jar

# Expose Auth Service port
EXPOSE 8081

# Run the application
ENTRYPOINT ["java", "-jar", "app.jar"]
