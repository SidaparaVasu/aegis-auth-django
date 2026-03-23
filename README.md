# AegisAuth: Advanced Security Boilerplate

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Django%204.2-green.svg)](https://www.djangoproject.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-hardened-red.svg)](#security-suite)

**AegisAuth** is a production-ready, security-first Django boilerplate designed for developers who need more than just "Login/Logout." It features a robust **Layered Architecture** (Repository-Service pattern), immutable audit trails, OTP-based multi-factor authentication, and advanced session management.

## Why AegisAuth?

Django's default authentication system provides basic login and session management, but modern applications often require stronger security controls and flexible policy management.

AegisAuth extends the standard authentication system with:

- Multi-factor authentication using OTP
- Password reuse prevention
- Brute-force attack detection
- Session tracking and token revocation
- Dynamic security policies through system configuration

This project aims to provide a **secure and extensible authentication foundation** for production-grade Django applications.

---

## Key Highlights

- **Advanced Security Suite:** Built-in protection against brute-force, password reuse, and account takeovers.
- **Core System Intelligence:** Centralized configuration and feature-flagging without redeploys.
- **Immutable Audit Trails:** Every critical security event is permanently recorded for forensic analysis.
- **Repository-Service Pattern:** Decoupled business logic from models and views for maximum testability.
- **OpenAPI 3.0 Integration:** Fully documented API with Swagger and Redoc out of the box.

---

## Feature Overview

- JWT-based authentication
- OTP-based login and verification
- Password history enforcement
- Brute-force protection with account lockouts
- Session tracking and revocation
- Dynamic system configuration
- Feature flag support
- Immutable audit logging
- Layered architecture (Repository-Service pattern)
- OpenAPI documentation (Swagger + Redoc)

---

## Security Suite

This project goes beyond standard Django authentication. Every security event is tracked and every policy is configurable:

| Feature | Description |
| :--- | :--- |
| **MFA / OTP** | Short-lived, purpose-specific OTPs for login and verification. |
| **Password History** | Prevents users from reusing their last `N` passwords (hashes only). |
| **Brute-Force Detection** | Monitors failed attempts and triggers temporary account lockouts. |
| **Session Tracking** | Maps every JWT token to an IP, User-Agent, and session JTI for easy revocation. |
| **Custom User Identity** | Case-insensitive email-based authentication with a lean `AuthUser` model. |

---

## Core System Utilities

Manage your production environment dynamically through the `core_system` app:

- **System Config:** Key-value store for app-wide settings (e.g., `OTP_EXPIRY`, `MAX_LOGIN_ATTEMPTS`).
- **Feature Flags:** Enable or disable features (like `MFA_LOGIN`) globally or for specific users.
- **System Event Log:** Infrastructure-level logging for operational monitoring (e.g., mail server failures).

---

## Architecture

The project follows a **Layered Architecture** to keep the codebase clean and maintainable as it grows:

```mermaid
graph TD

%% 1. Style Definitions (Classes)
classDef client  fill:#e8e4ff,stroke:#333,color:#000
classDef api     fill:#e3f2fd,stroke:#333,color:#000
classDef service fill:#e8f5e9,stroke:#333,color:#000
classDef data    fill:#fff3e0,stroke:#333,color:#000
classDef monitor fill:#fff9c4,stroke:#333,color:#000

%% 2. Structure & Components
subgraph Client ["Client Layer"]
    UI[Web UI - Alpine.js]:::client
    Mobile[External Clients/Mobile]:::client
end

subgraph API_Layer ["API Layer (Entry Points)"]
    JWT[JWT Middleware - Request Security]:::api
    Endpoints[v1 API Endpoints - DRF]:::api
    Docs[Interactive Docs - Swagger/Redoc]:::api
end

subgraph Service_Logic ["Business Logic (Services)"]
    AuthService[Auth Security Service]:::service
    CoreService[Core System Service]:::service
    Common[Common Utilities]:::service
end

subgraph Data_Layer ["Persistence Layer"]
    Repo[Repositories - Encapsulated DB Access]:::data
    ORM[Django ORM - Models]:::data
    DB[(Database - PostgreSQL/MySQL)]:::data
end

subgraph System_Monitoring ["Monitoring & Audit"]
    Audit[Immutable Audit Log]:::monitor
    Events[System Event Log]:::monitor
end

%% 3. Logical Flows
UI & Mobile --> JWT
JWT --> Endpoints
Endpoints --> AuthService & CoreService

AuthService & CoreService --> Repo
Repo --> ORM
ORM --> DB

%% 4. Dependencies
Common -.-> AuthService & CoreService
Docs -.->|API Schema| Endpoints

%% 5. Logging
AuthService -.-> Audit
CoreService -.-> Audit
CoreService -.-> Events
```

### Why Repository-Service Pattern?

The project uses a layered architecture to separate responsibilities:

- **Repositories:** Responsible for all DB queries. No more `User.objects.filter()` in your views.
- **Services:** Orchestrate business rules. E.g., `AuthService` handles hashing, OTP generation, and Email sending.
- **Common:** Shared response formats, custom exceptions, and pagination logic to ensure API consistency.

---

## Getting Started

### 1. Prerequisites
- Python 3.10+
- PostgreSQL or MySQL (Recommended) / SQLite (Dev)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/SidaparaVasu/aegis-auth-django.git
cd aegis-auth-django

# Create and activate a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Environment Setup
Create a `.env` file in the root directory based on `.env.example`:
```ini
DJANGO_SECRET_KEY=your-secret-key-here
DEBUG=True
DATABASE_URL=postgres://user:password@localhost:5432/aegisauth
# Optional: Email settings for OTP
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
```

### 4. Database & Migrations
```bash
python manage.py migrate
python manage.py createsuperuser
```

### 5. Run the Server
```bash
python manage.py runserver
```

---

## API Documentation

The API is fully versioned under `/api/v1/`. You can explore the interactive documentation at:

- **Swagger UI:** `{{BASE_URL}}/api/v1/docs/`
- **Redoc:** `{{BASE_URL}}/api/v1/redoc/`
- **OpenAPI Schema:** `{{BASE_URL}}/api/v1/schema/`

### API Usage Snippet
```
curl -X POST {{BASE_URL}}/api/v1/auth/login/ \
     -H "Content-Type: application/json" \
     -d '{"email": "admin@example.com", "password": "yourpassword"}'
```

---

## Project Structure

```text
├── apps/
│   ├── auth_security/   # Custom User, OTP, Session & Policy management
│   └── core_system/     # Dynamic Config, Feature Flags, Audit Logs
├── common/              # Shared Exceptions, Response wrappers & Validators
├── Core/
│   ├── settings/        # Environment-specific Django settings (base, dev, prod)
│   └── urls.py          # Master URL routing (UI & API)
├── frontend/            # Static UI (Alpine.js & Tailwind CSS)
└── manage.py            # Django entry point
```

---

## Contributing

We welcome contributions! Please ensure you follow the established **Repository-Service** pattern when adding new features and include unit tests in the respective `tests/` directories.

### Contribution Steps

1. Fork the repository
2. Create a feature branch
```bash 
git checkout -b feature/your-feature-name
```
3. Follow the Repository-Service architecture pattern
4. Add tests for new functionality
5. Submit a Pull Request
---

## License

Distributed under the MIT License. See `LICENSE` for more information.
