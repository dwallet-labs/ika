#!/usr/bin/env node
// Automated benchmark runner using Puppeteer
import http from 'http';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import puppeteer from 'puppeteer';

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

// Start server
function startServer() {
    return new Promise((resolve) => {
        const server = http.createServer((req, res) => {
            let filePath = path.join(__dirname, req.url === '/' ? 'benchmark.html' : req.url);
            if (!filePath.startsWith(__dirname)) {
                res.writeHead(403);
                res.end('Forbidden');
                return;
            }

            const ext = path.extname(filePath);
            const contentType = MIME_TYPES[ext] || 'application/octet-stream';

            fs.readFile(filePath, (err, content) => {
                if (err) {
                    res.writeHead(err.code === 'ENOENT' ? 404 : 500);
                    res.end(err.code === 'ENOENT' ? 'Not found' : 'Server error');
                    return;
                }

                res.writeHead(200, {
                    'Content-Type': contentType,
                    'Cross-Origin-Opener-Policy': 'same-origin',
                    'Cross-Origin-Embedder-Policy': 'require-corp',
                });
                res.end(content);
            });
        });

        server.listen(PORT, () => {
            console.log(`Server started on http://localhost:${PORT}`);
            resolve(server);
        });
    });
}

async function runBenchmark() {
    console.log('Starting benchmark server...');
    const server = await startServer();

    console.log('Launching browser...');
    const browser = await puppeteer.launch({
        headless: true,
        args: [
            '--enable-features=SharedArrayBuffer',
            '--no-sandbox',
            '--disable-setuid-sandbox',
        ]
    });

    const page = await browser.newPage();

    // Collect console logs
    const logs = [];
    page.on('console', msg => {
        const text = msg.text();
        logs.push(text);
        console.log('  [Browser]', text);
    });

    page.on('pageerror', err => {
        console.error('  [Page Error]', err.message);
    });

    console.log('\nNavigating to benchmark page...');
    await page.goto(`http://localhost:${PORT}`, { waitUntil: 'networkidle0' });

    // Run single-threaded benchmark
    console.log('\n=== SINGLE-THREADED BENCHMARK ===');
    await page.evaluate(() => window.runSingleThreaded());
    await page.waitForFunction(() => {
        const log = document.getElementById('log');
        return log && log.textContent.includes('Results:');
    }, { timeout: 120000 });

    // Wait a bit for everything to settle
    await new Promise(r => setTimeout(r, 2000));

    // Run parallel benchmark
    console.log('\n=== PARALLEL BENCHMARK ===');
    try {
        await page.evaluate(() => window.runParallel());
        await page.waitForFunction(() => {
            const log = document.getElementById('log');
            return log && (log.textContent.includes('Parallel') && log.textContent.split('Results:').length > 1);
        }, { timeout: 120000 });
    } catch (e) {
        console.log('Parallel benchmark failed or timed out:', e.message);
    }

    // Get final results
    const results = await page.evaluate(() => document.getElementById('log').textContent);
    console.log('\n=== FULL LOG ===\n', results);

    await browser.close();
    server.close();

    console.log('\nBenchmark complete!');
}

runBenchmark().catch(err => {
    console.error('Benchmark failed:', err);
    process.exit(1);
});
