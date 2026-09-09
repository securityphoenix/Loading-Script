#!/bin/bash
# Start script for Phoenix Scanner Service

set -e

echo "🚀 Starting Phoenix Scanner Service..."

# Check if .env exists
if [ ! -f .env ]; then
    echo "⚠️  .env file not found. Creating from template..."
    cp .env.example .env
    echo "✅ Created .env file"
    echo "⚠️  IMPORTANT: Please edit .env with your configuration before proceeding!"
    echo ""
    read -p "Press Enter after editing .env to continue, or Ctrl+C to exit..."
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p uploads logs data

# Build images
echo "🔨 Building Docker images..."
docker-compose build

# Start services
echo "🚀 Starting services..."
docker-compose up -d

# Wait for services to be healthy
echo "⏳ Waiting for services to be healthy..."
sleep 5

# Check health
echo "🏥 Checking service health..."
if curl -s http://localhost:8000/api/v1/ping > /dev/null 2>&1; then
    echo "✅ API is healthy!"
else
    echo "❌ API health check failed"
    echo "📋 Checking logs..."
    docker-compose logs api
    exit 1
fi

echo ""
echo "✅ Phoenix Scanner Service is running!"
echo ""
echo "📍 Service URLs:"
echo "   • API:          http://localhost:8000"
echo "   • Documentation: http://localhost:8000/docs"
echo "   • ReDoc:        http://localhost:8000/redoc"
echo "   • Flower:       http://localhost:5555"
echo ""
echo "📋 Useful commands:"
echo "   • View logs:    docker-compose logs -f"
echo "   • Stop:         docker-compose down"
echo "   • Restart:      docker-compose restart"
echo "   • Status:       docker-compose ps"
echo ""
echo "🔑 API Key: Check your .env file for API_KEY"
echo ""



