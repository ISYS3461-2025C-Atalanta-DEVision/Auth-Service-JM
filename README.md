# Auth Service - User Manual

## Overview

Authentication microservice handling user login, registration, and JWT token management.

---

## Deploy to Render

1. Push `auth-service` folder to GitHub
2. Create **Web Service** on Render
3. Set environment variables:

| Key | Value |
|-----|-------|
| `PORT` | `8081` |
| `EUREKA_URL` | `https://eureka:password@eureka-server-cofs.onrender.com/eureka/` |
| `REDIS_HOST` | `your-redis-host` |
| `REDIS_PORT` | `6379` |
| `REDIS_PASSWORD` | `your-redis-password` |
| `JWT_SECRET` | `your-256-bit-secret` |
| `MONGODB_URI` | `mongodb+srv://user:pass@cluster.mongodb.net/dbname` |
| `INTERNAL_API_KEY` | `your-internal-api-key` |
| `SPRING_PROFILES_ACTIVE` | `prod` |

---

## Run Locally

```bash
cd auth-service
mvn spring-boot:run
```

To connect to online Eureka:
```bash
EUREKA_URL=https://eureka:password@eureka-server-cofs.onrender.com/eureka/ mvn spring-boot:run
```

---

## Health Check

```bash
curl http://localhost:8081/actuator/health
```
