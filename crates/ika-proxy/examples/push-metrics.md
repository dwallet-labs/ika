# POST Request Examples for ika-proxy Metrics

This document provides comprehensive examples for pushing metrics to the ika-proxy using POST requests.

## Overview

The ika-proxy accepts Prometheus metrics via POST requests to the `/publish/metrics` endpoint. The proxy expects:

- **Endpoint**: `POST /publish/metrics`
- **Content-Type**: `application/x-protobuf` (Prometheus protobuf format)
- **Content-Encoding**: `snappy` (optional, for compression)
- **TLS**: Client certificate authentication (when peer validation is enabled)
- **Body**: Prometheus protobuf-encoded metrics

## Configuration Requirements

Before sending requests, ensure your ika-proxy is configured properly:

```yaml
# Basic configuration
network: mainnet
listen-address: 0.0.0.0:8080

# For development/testing (allows all connections)
dynamic-peers:
  hostname: localhost
  # No certificate-file/private-key = self-signed mode

# For production (requires valid client certificates)
dynamic-peers:
  certificate-file: /path/to/server.crt
  private-key: /path/to/server.key
static-peers:
  pub-keys:
    - name: my-validator
      peer-id: your-ed25519-public-key-hex
```

## Example 1: cURL with Raw Protobuf

### Basic Request (Self-Signed Mode)
```bash
#!/bin/bash

# Generate sample Prometheus protobuf data
# This would typically come from your metrics collection system

curl -X POST https://localhost:8080/publish/metrics \
  -H "Content-Type: application/x-protobuf" \
  -H "Content-Length: $(wc -c < metrics.pb)" \
  --data-binary @metrics.pb \
  --insecure  # Only for self-signed certificates
```

### With Client Certificate (Production Mode)
```bash
#!/bin/bash

curl -X POST https://sui-proxy.example.com:8080/publish/metrics \
  -H "Content-Type: application/x-protobuf" \
  -H "Content-Length: $(wc -c < metrics.pb)" \
  --cert client.crt \
  --key client.key \
  --cacert ca.crt \
  --data-binary @metrics.pb
```

### With Snappy Compression
```bash
#!/bin/bash

# Compress the protobuf data with snappy
snappy-compress metrics.pb metrics.pb.snappy

curl -X POST https://localhost:8080/publish/metrics \
  -H "Content-Type: application/x-protobuf" \
  -H "Content-Encoding: snappy" \
  -H "Content-Length: $(wc -c < metrics.pb.snappy)" \
  --data-binary @metrics.pb.snappy \
  --insecure
```

## Example 2: Python Client

### Basic Python Client
```python
#!/usr/bin/env python3

import requests
import ssl
from prometheus_client.core import CollectorRegistry
from prometheus_client.exposition import generate_latest
from prometheus_client import Counter, Histogram, Gauge
import snappy

def create_sample_metrics():
    """Create sample Prometheus metrics in protobuf format"""
    # Create a custom registry
    registry = CollectorRegistry()
    
    # Add some sample metrics
    counter = Counter('sui_transactions_total', 'Total transactions', registry=registry)
    counter.inc(100)
    
    gauge = Gauge('sui_active_validators', 'Active validators', registry=registry)
    gauge.set(42)
    
    histogram = Histogram('sui_block_processing_seconds', 'Block processing time', registry=registry)
    histogram.observe(0.5)
    histogram.observe(1.2)
    histogram.observe(0.8)
    
    # Generate protobuf format
    return generate_latest(registry)

def push_metrics_to_proxy(proxy_url, metrics_data, use_tls=False, cert_files=None, compress=False):
    """Push metrics to ika-proxy"""
    
    headers = {
        'Content-Type': 'application/x-protobuf',
    }
    
    data = metrics_data
    
    # Optional: Compress with snappy
    if compress:
        data = snappy.compress(data)
        headers['Content-Encoding'] = 'snappy'
    
    headers['Content-Length'] = str(len(data))
    
    # Configure TLS
    session = requests.Session()
    if use_tls and cert_files:
        session.cert = (cert_files['cert'], cert_files['key'])
        session.verify = cert_files.get('ca', True)
    elif not use_tls:
        session.verify = False  # For self-signed certificates
        
    try:
        response = session.post(
            f"{proxy_url}/publish/metrics",
            headers=headers,
            data=data,
            timeout=30
        )
        
        if response.status_code == 200:
            print(f"✅ Metrics pushed successfully")
            return True
        else:
            print(f"❌ Failed to push metrics: {response.status_code} - {response.text}")
            return False
            
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

if __name__ == "__main__":
    # Configuration
    PROXY_URL = "https://localhost:8080"
    
    # For development (self-signed)
    USE_TLS = False
    CERT_FILES = None
    
    # For production (with client certificates)
    # USE_TLS = True
    # CERT_FILES = {
    #     'cert': '/path/to/client.crt',
    #     'key': '/path/to/client.key',
    #     'ca': '/path/to/ca.crt'
    # }
    
    # Create and push metrics
    metrics = create_sample_metrics()
    success = push_metrics_to_proxy(
        PROXY_URL, 
        metrics, 
        use_tls=USE_TLS, 
        cert_files=CERT_FILES,
        compress=True  # Enable snappy compression
    )
    
    if success:
        print("Metrics delivery completed successfully")
    else:
        print("Failed to deliver metrics")
```

## Example 3: Simple Test Script

### Quick Test Script
```bash
#!/bin/bash

# Simple test script for ika-proxy metrics endpoint
# Usage: ./test-metrics-push.sh [proxy-url] [use-tls]

PROXY_URL=${1:-"https://localhost:8080"}
USE_TLS=${2:-"false"}

echo "🚀 Testing ika-proxy metrics endpoint"
echo "Proxy URL: $PROXY_URL"
echo "Use TLS: $USE_TLS"
echo ""

# Create a simple test payload (mock protobuf)
# In reality, this should be proper Prometheus protobuf data
TEST_PAYLOAD="test-metrics-data"
echo -n "$TEST_PAYLOAD" > /tmp/test-metrics.pb

# Prepare curl command
CURL_CMD="curl -X POST $PROXY_URL/publish/metrics"
CURL_CMD="$CURL_CMD -H 'Content-Type: application/x-protobuf'"
CURL_CMD="$CURL_CMD -H 'Content-Length: $(wc -c < /tmp/test-metrics.pb)'"
CURL_CMD="$CURL_CMD --data-binary @/tmp/test-metrics.pb"
CURL_CMD="$CURL_CMD -w 'HTTP Status: %{http_code}\nTime: %{time_total}s\n'"
CURL_CMD="$CURL_CMD -s"

if [ "$USE_TLS" = "false" ]; then
    CURL_CMD="$CURL_CMD --insecure"
fi

echo "📡 Sending test request..."
eval $CURL_CMD

# Cleanup
rm -f /tmp/test-metrics.pb

echo ""
echo "✅ Test completed"
```

## Example 4: Node.js Client

```javascript
const https = require('https');
const fs = require('fs');

class MetricsProxyClient {
    constructor(config) {
        this.config = {
            url: config.url,
            timeout: config.timeout || 30000,
            rejectUnauthorized: config.rejectUnauthorized !== false,
            ...config
        };
        
        // Setup TLS options
        this.httpsOptions = {
            rejectUnauthorized: this.config.rejectUnauthorized
        };
        
        if (config.cert && config.key) {
            this.httpsOptions.cert = fs.readFileSync(config.cert);
            this.httpsOptions.key = fs.readFileSync(config.key);
        }
        
        if (config.ca) {
            this.httpsOptions.ca = fs.readFileSync(config.ca);
        }
    }
    
    async pushMetrics(metricsData) {
        return new Promise((resolve, reject) => {
            const url = new URL(`${this.config.url}/publish/metrics`);
            
            const headers = {
                'Content-Type': 'application/x-protobuf',
                'Content-Length': metricsData.length
            };
            
            const options = {
                hostname: url.hostname,
                port: url.port || 443,
                path: url.pathname,
                method: 'POST',
                headers: headers,
                timeout: this.config.timeout,
                ...this.httpsOptions
            };
            
            const req = https.request(options, (res) => {
                let responseData = '';
                
                res.on('data', (chunk) => {
                    responseData += chunk;
                });
                
                res.on('end', () => {
                    if (res.statusCode === 200) {
                        console.log('✅ Metrics pushed successfully');
                        resolve(true);
                    } else {
                        console.error(`❌ Failed to push metrics: ${res.statusCode} - ${responseData}`);
                        reject(new Error(`HTTP ${res.statusCode}: ${responseData}`));
                    }
                });
            });
            
            req.on('error', (error) => {
                console.error('❌ Request failed:', error);
                reject(error);
            });
            
            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });
            
            req.write(metricsData);
            req.end();
        });
    }
}

// Usage example
async function main() {
    const client = new MetricsProxyClient({
        url: 'https://localhost:8080',
        rejectUnauthorized: false // Only for self-signed certs
    });
    
    try {
        // Your protobuf metrics data
        const metricsData = Buffer.from('your-protobuf-data');
        
        await client.pushMetrics(metricsData);
        console.log('Metrics delivery completed successfully');
    } catch (error) {
        console.error('Failed to deliver metrics:', error);
    }
}

main().catch(console.error);
```

## Example 5: Health Check Script

```bash
#!/bin/bash

# Health check script for ika-proxy
# Checks both the main endpoint and metrics endpoints

PROXY_HOST=${1:-"localhost"}
MAIN_PORT=${2:-"8080"}
METRICS_PORT=${3:-"9184"}
HISTOGRAM_PORT=${4:-"9185"}

echo "🏥 ika-proxy Health Check"
echo "========================="

# Check main endpoint (will fail without proper request, but should connect)
echo -n "Main endpoint ($PROXY_HOST:$MAIN_PORT): "
if timeout 5 bash -c "</dev/tcp/$PROXY_HOST/$MAIN_PORT" 2>/dev/null; then
    echo "✅ LISTENING"
else
    echo "❌ NOT ACCESSIBLE"
fi

# Check metrics endpoint
echo -n "Metrics endpoint ($PROXY_HOST:$METRICS_PORT): "
if curl -s "http://$PROXY_HOST:$METRICS_PORT/metrics" > /dev/null; then
    echo "✅ RESPONDING"
    
    # Show some key metrics
    echo "   Key metrics:"
    curl -s "http://$PROXY_HOST:$METRICS_PORT/metrics" | grep -E "(http_handler_hits|middleware_operations)" | head -3 | sed 's/^/   /'
else
    echo "❌ NOT RESPONDING"
fi

# Check histogram endpoint
echo -n "Histogram endpoint ($PROXY_HOST:$HISTOGRAM_PORT): "
if curl -s "http://$PROXY_HOST:$HISTOGRAM_PORT/metrics" > /dev/null; then
    echo "✅ RESPONDING"
else
    echo "❌ NOT RESPONDING"
fi

echo ""
echo "Health check completed"
```

## Common Issues and Solutions

### 1. **"invalid content-type header"**
```bash
# ❌ Wrong
curl -H "Content-Type: application/json" ...

# ✅ Correct
curl -H "Content-Type: application/x-protobuf" ...
```

### 2. **"unknown clients are not allowed"**
```bash
# Check if you need client certificates
# For development, use self-signed mode in config:
dynamic-peers:
  hostname: localhost
  # Don't specify certificate-file/private-key
```

### 3. **Connection refused**
```bash
# Check if proxy is running
ps aux | grep ika-proxy

# Check if port is listening
netstat -tlnp | grep :8080

# Check proxy logs
journalctl -u ika-proxy -f
```

### 4. **Invalid protobuf data**
```python
# Validate your protobuf data
from prometheus_client.exposition import generate_latest
from prometheus_client import Counter, CollectorRegistry

# Create proper protobuf data
registry = CollectorRegistry()
counter = Counter('test_metric', 'Test', registry=registry)
counter.inc()
protobuf_data = generate_latest(registry)
```

## Performance Tips

1. **Use compression** for large payloads:
   ```bash
   curl -H "Content-Encoding: snappy" --data-binary @compressed-metrics.pb
   ```

2. **Batch metrics** when possible to reduce overhead

3. **Monitor proxy performance**:
   ```bash
   curl -s http://localhost:9184/metrics | grep http_handler_duration
   ```

4. **Use connection pooling** in your client code

5. **Set appropriate timeouts** based on your network conditions

## Security Considerations

1. **Always use HTTPS** in production
2. **Validate client certificates** properly
3. **Monitor authentication failures**:
   ```bash
   curl -s http://localhost:9184/metrics | grep middleware_operations
   ```
4. **Rotate certificates** regularly
5. **Use proper CA certificates** instead of self-signed in production

## Testing Your Setup

### 1. Start the proxy
```bash
cd crates/ika-proxy
cargo run -- -c demo-config.yaml
```

### 2. Test connectivity
```bash
# Check if proxy is listening
curl -k https://localhost:8080/publish/metrics
# Should return 400 Bad Request (expected without proper data)
```

### 3. Check proxy metrics
```bash
# View proxy performance metrics
curl http://localhost:9184/metrics

# View histogram metrics  
curl http://localhost:9185/metrics
```

### 4. Send test metrics
```bash
# Use the Python example above or create your own protobuf data
python3 test-client.py
```

This comprehensive guide should help you successfully push metrics to your ika-proxy instance! 