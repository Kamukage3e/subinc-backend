# SubInc Backend

SubInc is a multi-tenant SaaS billing management system designed to handle subscriptions, payments, and billing operations for complex business models.

## Features

- **Multi-tenant Architecture**: Complete isolation between tenants
- **Plugin System**: Extensible architecture for payment providers
- **Subscription Management**: Create, modify, cancel subscriptions with proration
- **Payment Processing**: Secure payment handling with Stripe integration, robust idempotency, and comprehensive webhook support
- **Invoicing**: Generate professional invoices with tax handling, PDF export, and multi-currency support
- **Multi-Currency Support**: Handle transactions in multiple currencies
- **RBAC System**: Fine-grained role-based access control

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Go 1.21+ (for local development)

### Quick Start with Docker

The easiest way to get started is using Docker Compose:

```bash
# Clone the repository
git clone https://github.com/yourusername/subinc-backend.git
cd subinc-backend

# Start the services
docker-compose up -d

# View logs
docker-compose logs -f api
```

This will start:
- The SubInc API server on port 8080
- PostgreSQL database on port 5432
- Redis on port 6379
- PgAdmin web interface on port 5050

### Local Development Setup

For local development without Docker:

```bash
# Install dependencies
go mod download

# Create a .env file (use .env.example as a template)
cp .env.example .env
# Edit .env with your configuration

# Run database migrations
go run cmd/migrate/main.go -action=init -schema=schema.hcl
go run cmd/migrate/main.go -action=apply -schema=schema.hcl

# Run the application
go run cmd/main.go
```

## Configuration

SubInc is configured via environment variables. See `.env.example` for all available options.

Key configurations:

```
# Application Settings
APP_ENV=dev                  # dev, staging, prod
SERVICE_NAME=subinc-backend
PORT=8080

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=postgres
DB_NAME=subinc

# Redis Configuration
REDIS_ADDR=localhost:6379

# Payment Provider (Stripe)
STRIPE_API_KEY=
STRIPE_WEBHOOK_SECRET=
```

## API Documentation

When the server is running, API documentation is available at:

- Swagger UI: http://localhost:8080/docs
- OpenAPI Spec: http://localhost:8080/swagger.yaml

## Core Components

### Billing Management

The billing system is built around the following core components:

- **Accounts**: Manage billing accounts for tenants
- **Subscriptions**: Subscription plans and active subscriptions
- **Payments**: Process payments through integrated payment providers
- **Invoices**: Generate and manage invoices
- **Taxes**: Tax calculation and reporting
- **Discounts**: Coupons and promotional credits

### Security & RBAC

- Role-based access control for all API endpoints
- JWT authentication
- Audit logging for security events

### Multi-tenant Architecture

Tenant data is isolated at multiple levels:
- Database schema isolation
- Redis namespace isolation
- Request-scoped tenant context

## Plugin System

SubInc's plugin system allows for extensibility in key areas:

- **Payment Providers**: Add new payment processing capabilities
- **Invoice Formats**: Customize invoice generation
- **Tax Calculation**: Integrate with tax services

Plugins are dynamically loaded and configured through the database.

## Deployment & Scaling

### Docker Production Deployment

For production, customize the Docker Compose file:

```yaml
version: '3.8'

services:
  api:
    image: yourregistry/subinc-backend:latest
    environment:
      - APP_ENV=prod
      # Add other production settings
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '1'
          memory: 1G
```

### Kubernetes Deployment

For production Kubernetes deployment, use the provided Helm chart in `./charts/subinc-backend`.

## Roadmap

- [x] Complete Stripe integration with idempotency and webhook handling
- [ ] Complete PayPal integration
- [ ] Complete Braintree integration
- [ ] Add transaction reporting and analytics
- [x] Implement multi-currency support with automatic exchange rate updates
- [x] Enhance tax handling for international markets
- [x] Improve dunning system with configuration, manual retries, and dashboard
- [ ] Add comprehensive test coverage

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 