# Backend Engineering Skill

Purpose:

Build secure, scalable backend services for Qguard Helix.

Architecture:

* FastAPI
* PostgreSQL
* Supabase
* Redis
* Celery

Requirements:

* Async-first implementation
* Strong validation
* Type safety
* Secure APIs

API Standards:

* RESTful design
* Versioned endpoints
* Rate limiting
* Audit logging
* Structured responses

Security:

* JWT validation
* RBAC enforcement
* RLS enforcement
* Input sanitization
* Output filtering

Database Standards:

* Indexed queries
* Pagination
* Transactions
* Tenant isolation

Monitoring:

* Structured logging
* Metrics collection
* Error tracking
* Health checks

Avoid:

* N+1 queries
* Blocking operations
* Large payload responses
* Business logic in routes

Prefer:

* Service layer architecture
* Repository pattern
* Dependency injection
* Background workers
