#!/bin/bash

# Quick test script for ika-proxy metrics endpoint
# Usage: ./test-proxy.sh [proxy-url] [port]

set -e

# Configuration
PROXY_HOST=${1:-"localhost"}
PROXY_PORT=${2:-"8080"}
PROXY_URL="https://${PROXY_HOST}:${PROXY_PORT}"
METRICS_PORT="9184"
HISTOGRAM_PORT="9185"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 ika-proxy Quick Test${NC}"
echo -e "${BLUE}======================${NC}"
echo -e "Proxy URL: ${GREEN}${PROXY_URL}${NC}"
echo ""

# Function to check if a port is listening
check_port() {
    local host=$1
    local port=$2
    local name=$3
    
    echo -n "Checking $name ($host:$port): "
    if timeout 5 bash -c "</dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}✅ LISTENING${NC}"
        return 0
    else
        echo -e "${RED}❌ NOT ACCESSIBLE${NC}"
        return 1
    fi
}

# Function to test HTTP endpoint
test_http_endpoint() {
    local url=$1
    local name=$2
    
    echo -n "Testing $name: "
    if curl -s "$url" > /dev/null 2>&1; then
        echo -e "${GREEN}✅ RESPONDING${NC}"
        return 0
    else
        echo -e "${RED}❌ NOT RESPONDING${NC}"
        return 1
    fi
}

# Health checks
echo -e "${YELLOW}🏥 Health Checks${NC}"
echo "---------------"

# Check main proxy port
check_port "$PROXY_HOST" "$PROXY_PORT" "Main proxy endpoint"

# Check metrics endpoints
check_port "$PROXY_HOST" "$METRICS_PORT" "Metrics endpoint"
check_port "$PROXY_HOST" "$HISTOGRAM_PORT" "Histogram endpoint"

echo ""

# Test HTTP endpoints
echo -e "${YELLOW}📡 HTTP Endpoint Tests${NC}"
echo "---------------------"

test_http_endpoint "http://${PROXY_HOST}:${METRICS_PORT}/metrics" "Proxy metrics"
test_http_endpoint "http://${PROXY_HOST}:${HISTOGRAM_PORT}/metrics" "Histogram metrics"

echo ""

# Test main endpoint with dummy request
echo -e "${YELLOW}🧪 Main Endpoint Test${NC}"
echo "--------------------"

echo "Testing main endpoint with dummy request..."

# Create a dummy protobuf-like payload
TEMP_FILE=$(mktemp)
echo -n "dummy-protobuf-data" > "$TEMP_FILE"

# Test the main endpoint
echo -n "POST /publish/metrics: "
HTTP_STATUS=$(curl -w "%{http_code}" -o /dev/null -s \
    -X POST "${PROXY_URL}/publish/metrics" \
    -H "Content-Type: application/x-protobuf" \
    -H "Content-Length: $(wc -c < "$TEMP_FILE")" \
    --data-binary @"$TEMP_FILE" \
    --insecure \
    --connect-timeout 10 \
    --max-time 30 \
    2>/dev/null || echo "000")

case $HTTP_STATUS in
    200)
        echo -e "${GREEN}✅ SUCCESS (HTTP 200)${NC}"
        ;;
    400)
        echo -e "${YELLOW}⚠️  BAD REQUEST (HTTP 400) - Expected with dummy data${NC}"
        ;;
    403)
        echo -e "${YELLOW}⚠️  FORBIDDEN (HTTP 403) - Client cert required${NC}"
        ;;
    000)
        echo -e "${RED}❌ CONNECTION FAILED${NC}"
        ;;
    *)
        echo -e "${RED}❌ HTTP $HTTP_STATUS${NC}"
        ;;
esac

# Cleanup
rm -f "$TEMP_FILE"

echo ""

# Show some metrics if available
echo -e "${YELLOW}📊 Sample Metrics${NC}"
echo "----------------"

if curl -s "http://${PROXY_HOST}:${METRICS_PORT}/metrics" > /dev/null 2>&1; then
    echo "Recent proxy activity:"
    curl -s "http://${PROXY_HOST}:${METRICS_PORT}/metrics" | \
        grep -E "(http_handler_hits|middleware_operations|ika_proxy_uptime)" | \
        head -5 | \
        sed 's/^/  /'
else
    echo -e "${RED}❌ Cannot retrieve metrics${NC}"
fi

echo ""

# Summary and next steps
echo -e "${BLUE}📋 Summary${NC}"
echo "----------"

if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "400" ] || [ "$HTTP_STATUS" = "403" ]; then
    echo -e "${GREEN}✅ Proxy appears to be running and accessible${NC}"
    echo ""
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Use the Python test client for proper testing:"
    echo "   python3 examples/test-client.py --url $PROXY_URL"
    echo ""
    echo "2. Check proxy configuration:"
    echo "   cat demo-config.yaml"
    echo ""
    echo "3. Monitor proxy logs for detailed information"
    echo ""
    echo "4. For production, ensure proper TLS certificates are configured"
else
    echo -e "${RED}❌ Proxy is not accessible or not running${NC}"
    echo ""
    echo -e "${YELLOW}Troubleshooting:${NC}"
    echo "1. Check if ika-proxy is running:"
    echo "   ps aux | grep ika-proxy"
    echo ""
    echo "2. Start the proxy:"
    echo "   cargo run -- -c demo-config.yaml"
    echo ""
    echo "3. Check the configuration file:"
    echo "   cat demo-config.yaml"
    echo ""
    echo "4. Check firewall settings and port availability"
fi

echo ""
echo -e "${BLUE}Test completed!${NC}" 