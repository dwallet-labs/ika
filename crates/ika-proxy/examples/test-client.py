#!/usr/bin/env python3
"""
Test client for ika-proxy metrics endpoint

This script creates sample Prometheus metrics and sends them to the ika-proxy
using the correct protobuf format and headers.

Usage:
    python3 test-client.py [--url URL] [--compress] [--tls] [--cert CERT] [--key KEY] [--ca CA]

Examples:
    # Basic test with self-signed certificates
    python3 test-client.py --url https://localhost:8080

    # With compression
    python3 test-client.py --url https://localhost:8080 --compress

    # With client certificates (production)
    python3 test-client.py --url https://proxy.example.com:8080 --tls --cert client.crt --key client.key --ca ca.crt
"""

import argparse
import sys
import time
import requests
import urllib3
from prometheus_client.core import CollectorRegistry, REGISTRY
from prometheus_client.exposition import generate_latest
from prometheus_client import Counter, Histogram, Gauge, Info, Enum

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def create_sample_sui_metrics():
    """Create sample Sui-related Prometheus metrics"""
    # Create a custom registry to avoid conflicts with global registry
    registry = CollectorRegistry()
    
    # Sui transaction metrics
    tx_counter = Counter(
        'sui_transactions_total', 
        'Total number of transactions processed',
        ['transaction_type', 'status'],
        registry=registry
    )
    tx_counter.labels(transaction_type='transfer', status='success').inc(1250)
    tx_counter.labels(transaction_type='transfer', status='failed').inc(15)
    tx_counter.labels(transaction_type='publish', status='success').inc(89)
    tx_counter.labels(transaction_type='call', status='success').inc(2340)
    
    # Validator metrics
    validator_gauge = Gauge(
        'sui_active_validators', 
        'Number of active validators',
        registry=registry
    )
    validator_gauge.set(42)
    
    # Block processing metrics
    block_histogram = Histogram(
        'sui_block_processing_seconds',
        'Time spent processing blocks',
        ['validator_name'],
        registry=registry
    )
    block_histogram.labels(validator_name='validator-1').observe(0.5)
    block_histogram.labels(validator_name='validator-1').observe(1.2)
    block_histogram.labels(validator_name='validator-1').observe(0.8)
    block_histogram.labels(validator_name='validator-2').observe(0.7)
    block_histogram.labels(validator_name='validator-2').observe(0.9)
    
    # Network metrics
    network_gauge = Gauge(
        'sui_network_tps',
        'Transactions per second',
        registry=registry
    )
    network_gauge.set(156.7)
    
    # Consensus metrics
    consensus_counter = Counter(
        'sui_consensus_rounds_total',
        'Total consensus rounds',
        ['round_type'],
        registry=registry
    )
    consensus_counter.labels(round_type='normal').inc(5678)
    consensus_counter.labels(round_type='timeout').inc(23)
    
    # Gas metrics
    gas_histogram = Histogram(
        'sui_gas_used_per_transaction',
        'Gas used per transaction',
        buckets=[100, 500, 1000, 5000, 10000, 50000, 100000],
        registry=registry
    )
    gas_histogram.observe(250)
    gas_histogram.observe(1500)
    gas_histogram.observe(750)
    gas_histogram.observe(25000)
    
    # Node info
    node_info = Info(
        'sui_node_info',
        'Information about the Sui node',
        registry=registry
    )
    node_info.info({
        'version': '1.0.0',
        'network': 'mainnet',
        'node_type': 'validator',
        'build_commit': 'abc123def456'
    })
    
    # Node status
    node_status = Enum(
        'sui_node_status',
        'Current status of the Sui node',
        states=['starting', 'syncing', 'active', 'error'],
        registry=registry
    )
    node_status.state('active')
    
    return registry

def push_metrics_to_proxy(proxy_url, registry, use_tls=False, cert_files=None, compress=False, timeout=30):
    """Push metrics to ika-proxy"""
    
    # Generate protobuf data
    metrics_data = generate_latest(registry)
    
    print(f"📊 Generated {len(metrics_data)} bytes of metrics data")
    
    headers = {
        'Content-Type': 'application/x-protobuf',
        'Content-Length': str(len(metrics_data))
    }
    
    data = metrics_data
    
    # Optional: Compress with snappy
    if compress:
        try:
            import snappy
            data = snappy.compress(data)
            headers['Content-Encoding'] = 'snappy'
            headers['Content-Length'] = str(len(data))
            print(f"🗜️  Compressed to {len(data)} bytes ({(len(data)/len(metrics_data)*100):.1f}%)")
        except ImportError:
            print("⚠️  Snappy compression requested but python-snappy not installed")
            print("   Install with: pip install python-snappy")
            compress = False
    
    # Configure TLS
    session = requests.Session()
    if use_tls and cert_files:
        if cert_files.get('cert') and cert_files.get('key'):
            session.cert = (cert_files['cert'], cert_files['key'])
        if cert_files.get('ca'):
            session.verify = cert_files['ca']
        else:
            session.verify = True
    else:
        session.verify = False  # For self-signed certificates
        
    try:
        print(f"📡 Sending metrics to {proxy_url}/publish/metrics...")
        print(f"   Content-Type: {headers['Content-Type']}")
        print(f"   Content-Length: {headers['Content-Length']}")
        if compress:
            print(f"   Content-Encoding: {headers['Content-Encoding']}")
        
        start_time = time.time()
        response = session.post(
            f"{proxy_url}/publish/metrics",
            headers=headers,
            data=data,
            timeout=timeout
        )
        end_time = time.time()
        
        duration = end_time - start_time
        
        if response.status_code == 200:
            print(f"✅ Metrics pushed successfully in {duration:.2f}s")
            print(f"   Response: {response.text if response.text else 'OK'}")
            return True
        else:
            print(f"❌ Failed to push metrics: HTTP {response.status_code}")
            print(f"   Response: {response.text}")
            return False
            
    except requests.exceptions.SSLError as e:
        print(f"❌ SSL/TLS error: {e}")
        print("   Try using --tls with proper certificates or check proxy configuration")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"❌ Connection error: {e}")
        print("   Check if the proxy is running and accessible")
        return False
    except requests.exceptions.Timeout as e:
        print(f"❌ Request timeout: {e}")
        print("   Try increasing timeout or check network connectivity")
        return False
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return False

def check_proxy_health(proxy_url, timeout=10):
    """Check if the proxy is responding"""
    try:
        # Try to connect to the main endpoint (will likely fail but shows connectivity)
        response = requests.get(
            f"{proxy_url}/publish/metrics",
            timeout=timeout,
            verify=False
        )
        # Any response (even error) means the proxy is running
        print(f"✅ Proxy is responding (HTTP {response.status_code})")
        return True
    except requests.exceptions.ConnectionError:
        print(f"❌ Cannot connect to proxy at {proxy_url}")
        return False
    except requests.exceptions.Timeout:
        print(f"❌ Proxy at {proxy_url} is not responding (timeout)")
        return False
    except Exception as e:
        print(f"⚠️  Unexpected error checking proxy: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Test client for ika-proxy metrics endpoint',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://localhost:8080
  %(prog)s --url https://localhost:8080 --compress
  %(prog)s --url https://proxy.example.com:8080 --tls --cert client.crt --key client.key
        """
    )
    
    parser.add_argument(
        '--url', 
        default='https://localhost:8080',
        help='Proxy URL (default: https://localhost:8080)'
    )
    parser.add_argument(
        '--compress', 
        action='store_true',
        help='Enable snappy compression'
    )
    parser.add_argument(
        '--tls', 
        action='store_true',
        help='Use proper TLS validation (default: accept self-signed)'
    )
    parser.add_argument(
        '--cert', 
        help='Client certificate file for TLS authentication'
    )
    parser.add_argument(
        '--key', 
        help='Client private key file for TLS authentication'
    )
    parser.add_argument(
        '--ca', 
        help='CA certificate file for TLS validation'
    )
    parser.add_argument(
        '--timeout', 
        type=int, 
        default=30,
        help='Request timeout in seconds (default: 30)'
    )
    parser.add_argument(
        '--health-check', 
        action='store_true',
        help='Only check if proxy is responding'
    )
    
    args = parser.parse_args()
    
    print("🚀 ika-proxy Test Client")
    print("=" * 40)
    print(f"Target URL: {args.url}")
    print(f"Compression: {'Enabled' if args.compress else 'Disabled'}")
    print(f"TLS Mode: {'Strict' if args.tls else 'Accept Self-Signed'}")
    if args.cert:
        print(f"Client Cert: {args.cert}")
    if args.key:
        print(f"Client Key: {args.key}")
    if args.ca:
        print(f"CA Cert: {args.ca}")
    print()
    
    # Health check only
    if args.health_check:
        print("🏥 Performing health check...")
        if check_proxy_health(args.url, args.timeout):
            sys.exit(0)
        else:
            sys.exit(1)
    
    # Check proxy connectivity first
    print("🏥 Checking proxy connectivity...")
    if not check_proxy_health(args.url, args.timeout):
        print("❌ Cannot reach proxy. Please check:")
        print("   1. Proxy is running")
        print("   2. URL is correct")
        print("   3. Network connectivity")
        print("   4. Firewall settings")
        sys.exit(1)
    
    # Prepare certificate files
    cert_files = None
    if args.tls or args.cert or args.key or args.ca:
        cert_files = {}
        if args.cert:
            cert_files['cert'] = args.cert
        if args.key:
            cert_files['key'] = args.key
        if args.ca:
            cert_files['ca'] = args.ca
    
    # Create sample metrics
    print("📊 Creating sample Sui metrics...")
    registry = create_sample_sui_metrics()
    
    # Push metrics
    success = push_metrics_to_proxy(
        args.url,
        registry,
        use_tls=args.tls,
        cert_files=cert_files,
        compress=args.compress,
        timeout=args.timeout
    )
    
    if success:
        print("\n🎉 Test completed successfully!")
        print("\nNext steps:")
        print("1. Check proxy metrics: curl http://localhost:9184/metrics")
        print("2. Check histogram metrics: curl http://localhost:9185/metrics")
        print("3. Verify metrics were forwarded to your remote write endpoint")
        sys.exit(0)
    else:
        print("\n💥 Test failed!")
        print("\nTroubleshooting:")
        print("1. Check proxy logs for errors")
        print("2. Verify proxy configuration")
        print("3. Check TLS certificate setup")
        print("4. Ensure proper content-type and protobuf format")
        sys.exit(1)

if __name__ == "__main__":
    main() 