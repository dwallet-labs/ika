// Simple HTTP server with COOP/COEP headers for testing parallel WASM
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 8080;

const MIME_TYPES = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.mjs': 'text/javascript',
    '.wasm': 'application/wasm',
    '.css': 'text/css',
    '.json': 'application/json',
};

const server = http.createServer((req, res) => {
    let filePath = path.join(__dirname, req.url === '/' ? 'benchmark.html' : req.url);

    // Security: prevent directory traversal
    if (!filePath.startsWith(__dirname)) {
        res.writeHead(403);
        res.end('Forbidden');
        return;
    }

    const ext = path.extname(filePath);
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';

    fs.readFile(filePath, (err, content) => {
        if (err) {
            if (err.code === 'ENOENT') {
                res.writeHead(404);
                res.end('Not found: ' + req.url);
            } else {
                res.writeHead(500);
                res.end('Server error');
            }
            return;
        }

        // Required headers for SharedArrayBuffer (parallel WASM)
        res.writeHead(200, {
            'Content-Type': contentType,
            'Cross-Origin-Opener-Policy': 'same-origin',
            'Cross-Origin-Embedder-Policy': 'require-corp',
        });
        res.end(content);
    });
});

server.listen(PORT, () => {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║         WASM Benchmark Server                                 ║
╠══════════════════════════════════════════════════════════════╣
║  Open in browser: http://localhost:${PORT}                       ║
║                                                              ║
║  Headers enabled:                                             ║
║  - Cross-Origin-Opener-Policy: same-origin                   ║
║  - Cross-Origin-Embedder-Policy: require-corp                ║
║                                                              ║
║  These headers are required for SharedArrayBuffer            ║
║  which is needed for parallel WASM execution.                ║
╚══════════════════════════════════════════════════════════════╝
`);
});
