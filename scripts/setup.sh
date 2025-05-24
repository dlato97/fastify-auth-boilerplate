#!/bin/bash

# Fastify Auth Boilerplate Setup Script
# This script automates the initial setup process

set -e

echo "🚀 Setting up Fastify Auth Boilerplate..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

success() {
    echo -e "${GREEN}✅ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

error() {
    echo -e "${RED}❌ $1${NC}"
    exit 1
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check prerequisites
check_prerequisites() {
    info "Checking prerequisites..."

    if ! command_exists node; then
        error "Node.js is not installed. Please install Node.js 20+ first."
    fi

    NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
    if [ "$NODE_VERSION" -lt 20 ]; then
        error "Node.js version 20+ is required. Current version: $(node -v)"
    fi

    if ! command_exists npm; then
        error "npm is not installed."
    fi

    if ! command_exists docker; then
        error "Docker is not installed. Please install Docker first."
    fi

    if ! command_exists docker-compose; then
        if ! docker compose version >/dev/null 2>&1; then
            error "Docker Compose is not available. Please install Docker Compose."
        fi
    fi

    success "All prerequisites met!"
}

# Install dependencies
install_dependencies() {
    info "Installing dependencies..."
    npm install
    success "Dependencies installed!"
}

# Setup environment variables
setup_environment() {
    info "Setting up environment variables..."

    if [ ! -f .env ]; then
        cp .env.example .env
        info "Created .env file from .env.example"

        # Generate secure secrets
        JWT_ACCESS_SECRET=$(openssl rand -hex 32)
        JWT_REFRESH_SECRET=$(openssl rand -hex 32)
        SESSION_SECRET=$(openssl rand -hex 32)

        # Update .env file with generated secrets
        if command_exists openssl; then
            sed -i.bak "s/your-super-secret-access-key-min-32-chars/$JWT_ACCESS_SECRET/" .env
            sed -i.bak "s/your-super-secret-refresh-key-min-32-chars/$JWT_REFRESH_SECRET/" .env
            sed -i.bak "s/your-session-secret-key-min-32-chars/$SESSION_SECRET/" .env
            rm .env.bak 2>/dev/null || true
            success "Generated secure JWT and session secrets"
        else
            warning "OpenSSL not found. Please update JWT secrets in .env manually."
        fi
    else
        warning ".env file already exists. Skipping environment setup."
    fi
}

# Start Docker services
start_docker_services() {
    info "Starting Docker services..."

    # Check if services are already running
    if docker-compose ps | grep -q "Up"; then
        warning "Some services are already running."
        read -p "Do you want to restart them? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            docker-compose down
            docker-compose up -d
        fi
    else
        docker-compose up -d
    fi

    # Wait for services to be ready
    info "Waiting for services to be ready..."
    sleep 10

    # Check PostgreSQL
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
            success "PostgreSQL is ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            error "PostgreSQL failed to start after 30 attempts"
        fi
        sleep 2
    done

    # Check Redis
    for i in {1..30}; do
        if docker-compose exec -T redis redis-cli ping >/dev/null 2>&1; then
            success "Redis is ready!"
            break
        fi
        if [ $i -eq 30 ]; then
            error "Redis failed to start after 30 attempts"
        fi
        sleep 2
    done
}

# Setup database
setup_database() {
    info "Setting up database..."

    # Generate Prisma client
    npm run db:generate
    success "Prisma client generated!"

    # Run migrations
    npm run db:migrate
    success "Database migrations completed!"

    # Seed database
    if [ -f "prisma/seed.ts" ]; then
        npm run db:seed
        success "Database seeded!"
    else
        info "No seed file found, skipping database seeding."
    fi
}

# Create initial admin user
create_admin_user() {
    info "Creating initial admin user..."

    read -p "Enter admin email: " ADMIN_EMAIL
    read -s -p "Enter admin password: " ADMIN_PASSWORD
    echo

    # This would typically be done through a seed script or API call
    # For now, we'll create a simple Node.js script
    cat > create-admin.js << EOF
const { PrismaClient } = require('@prisma/client');
const { hash } = require('@node-rs/argon2');

async function createAdmin() {
  const prisma = new PrismaClient();

  try {
    // Check if admin role exists
    let adminRole = await prisma.role.findUnique({
      where: { name: 'admin' }
    });

    if (!adminRole) {
      adminRole = await prisma.role.create({
        data: {
          name: 'admin',
          displayName: 'Administrator',
          description: 'Full system access',
          permissions: [
            'users:read', 'users:write', 'users:delete', 'users:manage',
            'roles:read', 'roles:write', 'roles:delete', 'roles:manage',
            'system:admin', 'analytics:view', 'settings:write'
          ],
          isSystem: true
        }
      });
    }

    // Hash password
    const hashedPassword = await hash('$ADMIN_PASSWORD');

    // Create admin user
    const adminUser = await prisma.user.create({
      data: {
        email: '$ADMIN_EMAIL',
        password: hashedPassword,
        isActive: true,
        isVerified: true,
        roles: {
          create: {
            roleId: adminRole.id
          }
        }
      }
    });

    console.log('Admin user created successfully!');
    console.log('Email:', adminUser.email);
    console.log('ID:', adminUser.id);

  } catch (error) {
    if (error.code === 'P2002') {
      console.log('Admin user already exists with this email.');
    } else {
      console.error('Error creating admin user:', error.message);
      process.exit(1);
    }
  } finally {
    await prisma.\$disconnect();
  }
}

createAdmin();
EOF

    node create-admin.js
    rm create-admin.js
    success "Admin user created!"
}

# Display service URLs
display_urls() {
    echo
    success "Setup completed successfully! 🎉"
    echo
    info "Available services:"
    echo "📱 API Server: http://localhost:3000"
    echo "📚 API Docs: http://localhost:3000/documentation"
    echo "🗄️  Prisma Studio: http://localhost:5555"
    echo "📧 MailHog: http://localhost:8025"
    echo "🔧 Adminer: http://localhost:8080"
    echo "❤️  Health Check: http://localhost:3000/health"
    echo
    info "To start the development server:"
    echo "npm run dev"
    echo
    info "To open Prisma Studio:"
    echo "npm run db:studio"
    echo
    info "To view logs:"
    echo "npm run docker:logs"
}

# Cleanup function
cleanup() {
    if [ $? -ne 0 ]; then
        error "Setup failed! Check the logs above for details."
        echo
        info "To restart the setup:"
        echo "./scripts/setup.sh"
        echo
        info "To clean up and start over:"
        echo "docker-compose down -v"
        echo "rm -f .env"
        echo "./scripts/setup.sh"
    fi
}

# Set trap for cleanup
trap cleanup EXIT

# Main setup flow
main() {
    echo "🏗️  Fastify Auth Boilerplate Setup"
    echo "=================================="
    echo

    check_prerequisites
    install_dependencies
    setup_environment
    start_docker_services
    setup_database

    echo
    read -p "Do you want to create an initial admin user? (Y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
        create_admin_user
    fi

    display_urls
}

# Run main function
main "$@"
