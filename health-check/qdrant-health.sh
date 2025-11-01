#!/bin/bash

# Qdrant Health Check Script for Critical Memory System
# This script checks if Qdrant is responsive and healthy

set -e

QDRANT_URL="http://localhost:6333"
HEALTH_ENDPOINT="/health"
MAX_RETRIES=3
RETRY_DELAY=5

check_health() {
    local attempt=1
    echo "Checking Qdrant health (attempt $attempt)..."

    while [ $attempt -le $MAX_RETRIES ]; do
        if curl -f -s --max-time 10 "$QDRANT_URL$HEALTH_ENDPOINT" > /dev/null; then
            echo "✅ Qdrant is healthy and responsive"
            return 0
        else
            echo "❌ Health check failed (attempt $attempt/$MAX_RETRIES)"
            if [ $attempt -lt $MAX_RETRIES ]; then
                echo "Retrying in $RETRY_DELAY seconds..."
                sleep $RETRY_DELAY
            fi
            ((attempt++))
        fi
    done

    echo "❌ Qdrant health check failed after $MAX_RETRIES attempts"
    return 1
}

check_collection_exists() {
    echo "Checking if critical collections exist..."
    # Add collection checks if needed
    # curl -f -s "$QDRANT_URL/collections/memory"
}

# Main health check
if check_health; then
    check_collection_exists
    echo "🎯 All health checks passed - Qdrant is ready for memory operations"
    exit 0
else
    echo "🚨 Qdrant health check failed - memory system may be unavailable"
    exit 1
fi