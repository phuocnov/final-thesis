/*
 * Copyright 2026 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const fs = require('fs');
const http = require('http');
const path = require('path');

const PORT = parseInt(process.env.PORT, 10) || 8080;
const USERS_FILE =
  process.env.USERS_FILE || path.join(__dirname, 'data', 'users.json');
const MAX_BODY_BYTES = 1024 * 1024; // 1 MiB

/**
 * Emits a structured JSON log line, matching the format used by the other
 * Node.js services in this repository.
 */
function log(severity, message, extra = {}) {
  console.log(JSON.stringify({ severity, message, ...extra }));
}

/**
 * Loads the sample accounts from the JSON file and indexes them by username.
 * This is a mock service, so the file is read once at startup and there is no
 * database involved.
 */
function loadUsers(file) {
  const raw = fs.readFileSync(file, 'utf8');
  const users = JSON.parse(raw);

  if (!Array.isArray(users)) {
    throw new Error(`${file} must contain a JSON array of users`);
  }

  const index = new Map();
  for (const user of users) {
    if (!user || typeof user.username !== 'string') {
      throw new Error(`${file} contains a user without a username`);
    }
    index.set(user.username, user);
  }
  return index;
}

/**
 * Reads and parses a JSON request body. Rejects with a status code so callers
 * can map the failure to an HTTP response.
 */
function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];

    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        const err = new Error('request body too large');
        err.statusCode = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (body.trim() === '') {
        const err = new Error('request body is empty');
        err.statusCode = 400;
        reject(err);
        return;
      }
      try {
        resolve(JSON.parse(body));
      } catch (err) {
        const parseError = new Error('request body is not valid JSON');
        parseError.statusCode = 400;
        reject(parseError);
      }
    });

    req.on('error', reject);
  });
}

function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

/**
 * Builds an opaque, non-cryptographic token. This service is a mock: the token
 * is only meant to look like one, it is not signed and is not verified
 * anywhere.
 */
function buildMockToken(username) {
  return (
    'mock-token-' +
    Buffer.from(`${username}:${Date.now()}`).toString('base64url')
  );
}

/**
 * POST /login
 *
 * Body: {"username": "...", "password": "..."}
 * 200: {"token": "...", "user": {"username", "name", "email"}}
 * 400: malformed or incomplete request body
 * 401: unknown user or wrong password
 */
async function handleLogin(req, res, users) {
  let body;
  try {
    body = await readJsonBody(req);
  } catch (err) {
    sendJson(res, err.statusCode || 400, { error: err.message });
    return;
  }

  const { username, password } = body || {};
  if (
    typeof username !== 'string' ||
    username.trim() === '' ||
    typeof password !== 'string' ||
    password === ''
  ) {
    sendJson(res, 400, { error: 'username and password are required' });
    return;
  }

  const user = users.get(username);
  if (!user || user.password !== password) {
    log('warning', 'login failed', { username });
    sendJson(res, 401, { error: 'invalid credentials' });
    return;
  }

  const token = buildMockToken(user.username);
  log('info', 'login succeeded', { username: user.username });
  sendJson(res, 200, {
    token,
    user: {
      username: user.username,
      name: user.name,
      email: user.email,
    },
  });
}

/**
 * GET /healthz - used by the Kubernetes readiness and liveness probes.
 */
function handleHealth(res) {
  sendJson(res, 200, { status: 'ok' });
}

function main() {
  const users = loadUsers(USERS_FILE);
  log('info', 'loaded sample accounts', {
    usersFile: USERS_FILE,
    count: users.size,
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    const route = `${req.method} ${url.pathname}`;

    switch (route) {
      case 'GET /healthz':
        handleHealth(res);
        break;
      case 'POST /login':
        handleLogin(req, res, users).catch((err) => {
          log('error', 'unhandled login error', { error: err.message });
          if (!res.headersSent) {
            sendJson(res, 500, { error: 'internal server error' });
          }
        });
        break;
      default:
        sendJson(res, 404, { error: 'not found' });
        break;
    }
  });

  server.listen(PORT, '0.0.0.0', () => {
    log('info', `authservice listening on port ${PORT}`);
  });

  const shutdown = (signal) => {
    log('info', `received ${signal}, shutting down`);
    server.close(() => process.exit(0));
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main();
