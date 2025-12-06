# Auth Service - User Manual

## Overview

Authentication microservice handling user login, registration, and JWT token management.

---

## Connect to Online Eureka Server

In `src/main/resources/application.yml`, update the Eureka configuration:

```yaml
eureka:
  client:
    service-url:
      defaultZone: https://eureka:<password>@eureka-server-cofs.onrender.com/eureka/
```

Replace `<password>` with your Eureka password.

---

## Connect to Online Redis

```yaml
spring:
  data:
    redis:
      host: <your-redis-host>
      port: 6379
      password: <your-redis-password>
```

---

## Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `EUREKA_USERNAME` | Eureka auth username | `eureka` |
| `EUREKA_PASSWORD` | Eureka auth password | `your-password` |
| `REDIS_HOST` | Redis server host | `redis-12345.c1.us-east-1-2.ec2.cloud.redislabs.com` |
| `REDIS_PASSWORD` | Redis password | `your-redis-password` |
| `JWT_SECRET` | Secret for signing tokens | `your-256-bit-secret` |

---

## Run Locally

```bash
cd auth-service
mvn spring-boot:run
```

---

## Health Check

```bash
curl http://localhost:8081/actuator/health
```
