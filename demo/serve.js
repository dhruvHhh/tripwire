// Serves the demo page on http://localhost:8080.
// Content scripts don't run on file:// pages, so the page has to be served.
//
//   node demo/serve.js

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');

const PORT = 8080;
const PAGE = path.join(__dirname, 'links.html');

http
  .createServer((request, response) => {
    // Every path returns the same page, so its relative links work too.
    fs.readFile(PAGE, (error, html) => {
      if (error) {
        response.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        response.end(String(error));
        return;
      }
      response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      response.end(html);
    });
  })
  .listen(PORT, '127.0.0.1', () => {
    console.log(`Tripwire demo page: http://localhost:${PORT}/`);
  });
