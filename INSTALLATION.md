# 🚀 Fastify Auth Boilerplate - Installation Guide

## Prerequisites

- **Node.js 20+** (LTS recommended)
- **Docker & Docker Compose** (for local development)
- **Git** (for version control)

## Quick Start (Automated Setup)

```bash
# 1. Clone the repository
git clone <your-repository-url>
cd fastify-auth-boilerplate

# 2. Make setup script executable
chmod +x scripts/setup.sh

# 3. Run automated setup
./scripts/setup.sh
```

The script will:
- Install dependencies
- Setup environment variables
- Start Docker services
- Run database migrations
- Seed initial data
- Create admin user

## Manual Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Environment Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit environment variables
nano .env
```

**Important:** Generate secure secrets for JWT tokens:

```bash
# Generate JWT secrets (Linux/macOS)
openssl rand -hex 32

# Or use Node.js
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. Start Services

```bash
# Start PostgreSQL, Redis, MailHog, Adminer
docker-compose up -d

# Verify services are running
docker-compose ps
```

### 4. Database Setup

```bash
# Generate Prisma client
npm run db:generate

# Run migrations
npm run db:migrate

# Seed database with initial data
npm run db:seed
```

### 5. Start Development Server

```bash
# Start in development mode
npm run dev

# Or build and start production
npm run build
npm start
```

## Available Services

| Service | URL | Description |
|---------|-----|-------------|
| **API Server** | http://localhost:3000 | Main API server |
| **API Documentation** | http://localhost:3000/documentation | Swagger UI |
| **Health Check** | http://localhost:3000/health | Server health status |
| **Prisma Studio** | http://localhost:5555 | Database GUI |
| **MailHog** | http://localhost:8025 | Email testing |
| **Adminer** | http://localhost:8080 | Database admin |

## Default Accounts

After seeding, these accounts are available:

| Role | Email | Password | Permissions |
|------|-------|----------|-------------|
| **Super Admin** | admin@example.com | Admin123!@# | Full system access |
| **Moderator** | moderator@example.com | Moderator123! | User management |
| **User** | user@example.com | User123! | Standard access |

> ⚠️ **Security**: Change all default passwords before production deployment!

## API Endpoints

### Authentication

```bash
# Register new user
POST /api/v1/auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe"
}

# Login
POST /api/v1/auth/login
{
  "email": "user@example.com",
  "password": "SecurePass123!"
}

# Get profile (requires auth)
GET /api/v1/auth/me
Authorization: Bearer <token>

# Enable 2FA
POST /api/v1/auth/2fa/setup
Authorization: Bearer <token>
{
  "password": "current-password"
}
```

### User Management (Admin only)

```bash
# Get users list
GET /api/v1/users?page=1&limit=20
Authorization: Bearer <admin-token>

# Create user
POST /api/v1/users
Authorization: Bearer <admin-token>
{
  "email": "newuser@example.com",
  "password": "SecurePass123!",
  "roles": ["user"]
}
```

## Development Commands

### Database

```bash
npm run db:generate     # Generate Prisma client
npm run db:push         # Push schema changes (dev)
npm run db:migrate      # Create and run migrations
npm run db:studio       # Open Prisma Studio
npm run db:seed         # Seed database
npm run db:reset        # Reset database
```

### Development

```bash
npm run dev            # Start development server
npm run build          # Build for production
npm run start          # Start production server
npm run type-check     # TypeScript check only
```

### Code Quality

```bash
npm run lint           # Lint code
npm run lint:fix       # Fix linting issues
npm run format         # Format code with Prettier
```

### Testing

```bash
npm run test           # Run tests
npm run test:ui        # Open test UI
npm run test:coverage  # Run with coverage
```

### Docker

```bash
npm run docker:up      # Start all services
npm run docker:down    # Stop all services
npm run docker:logs    # View logs
```

## Environment Variables

### Required Variables

```bash
# Database
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/fastify_auth"

# Redis
REDIS_URL="redis://:redis123@localhost:6379"

# JWT Secrets (MUST BE CHANGED)
JWT_ACCESS_SECRET="your-32-char-secret-here"
JWT_REFRESH_SECRET="your-32-char-secret-here"
SESSION_SECRET="your-32-char-secret-here"
```

### Optional Variables

```bash
# Server
NODE_ENV="development"
PORT=3000
HOST="localhost"

# Email (MailHog for development)
SMTP_HOST="localhost"
SMTP_PORT=1025
SMTP_FROM="noreply@yourapp.com"

# Features
ENABLE_2FA=true
ENABLE_EMAIL_VERIFICATION=true
SWAGGER_ENABLED=true
```

## Production Deployment

### 1. Environment Setup

```bash
# Production environment variables
NODE_ENV=production
DATABASE_URL="postgresql://user:pass@prod-host:5432/dbname"
REDIS_URL="redis://user:pass@prod-host:6379"

# Use strong, unique secrets
JWT_ACCESS_SECRET="production-secret-32-chars-min"
JWT_REFRESH_SECRET="production-secret-32-chars-min"
SESSION_SECRET="production-secret-32-chars-min"

# Production email service
SMTP_HOST="smtp.sendgrid.net"
SMTP_PORT=587
SMTP_USER="apikey"
SMTP_PASS="your-sendgrid-api-key"
```

### 2. Build and Deploy

```bash
# Build application
npm run build

# Start production server
npm start

# Or use PM2 for process management
npm install -g pm2
pm2 start dist/index.js --name "fastify-auth"
```

### 3. Docker Production

```dockerfile
# Build production image
docker build -t fastify-auth .

# Run container
docker run -p 3000:3000 \
  -e NODE_ENV=production \
  -e DATABASE_URL="..." \
  -e JWT_ACCESS_SECRET="..." \
  fastify-auth
```

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Check what's using the port
lsof -i :3000
# Kill the process
kill -9 <PID>
```

**Database connection failed:**
```bash
# Check if PostgreSQL is running
docker-compose ps postgres
# Check logs
docker-compose logs postgres
```

**Redis connection failed:**
```bash
# Check Redis status
docker-compose ps redis
# Test connection
redis-cli -h localhost -p 6379 ping
```

**Prisma client issues:**
```bash
# Regenerate client
npm run db:generate
# Reset database
npm run db:reset
```

### Debugging

Enable debug logging:
```bash
# In .env file
LOG_LEVEL="debug"
ENABLE_REQUEST_LOGGING=true
```

View detailed logs:
```bash
# Application logs
npm run dev

# Docker service logs
npm run docker:logs

# Specific service logs
docker-compose logs -f postgres
docker-compose logs -f redis
```

## Security Checklist

- [ ] Change all default passwords
- [ ] Use strong JWT secrets (32+ characters)
- [ ] Enable HTTPS in production
- [ ] Configure proper CORS origins
- [ ] Set up rate limiting
- [ ] Enable audit logging
- [ ] Configure email verification
- [ ] Set up 2FA for admin accounts
- [ ] Regular security updates
- [ ] Monitor for suspicious activity

## Support

- **Documentation**: Check the README.md and code comments
- **Issues**: Create issues in the repository
- **Security**: Report security issues privately

---

Happy coding! 🎉
