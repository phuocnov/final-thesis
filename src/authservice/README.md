# authservice

A mock authentication microservice written in Node.js. It has no database and
no external dependencies: the sample accounts live in
[`data/users.json`](./data/users.json) and are loaded into memory at startup.

> **This service is a mock.** Passwords are stored and compared in plaintext
> and the returned token is an opaque, unsigned string. Do not use it as-is in
> production.

## Endpoints

### `POST /login`

Request body:

```json
{
  "username": "alice",
  "password": "password123"
}
```

Responses:

| Status | Body | When |
| --- | --- | --- |
| `200` | `{"token":"mock-token-...","user":{"username":"alice","name":"Alice Nguyen","email":"alice@example.com"}}` | Credentials match |
| `400` | `{"error":"username and password are required"}` | Missing field or malformed JSON |
| `401` | `{"error":"invalid credentials"}` | User not found or wrong password |

### `GET /healthz`

Returns `200 {"status":"ok"}`. Used by the Kubernetes readiness and liveness
probes.

## Sample accounts

| Username | Password |
| --- | --- |
| `alice` | `password123` |
| `bob` | `hunter2` |
| `admin` | `admin123` |

## Configuration

| Environment variable | Default | Description |
| --- | --- | --- |
| `PORT` | `8080` | HTTP port to listen on |
| `USERS_FILE` | `./data/users.json` | Path to the JSON file with sample accounts |

## Running locally

```sh
cd src/authservice
npm start
```

```sh
# Successful login
curl -i -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'

# Unknown user -> 401
curl -i -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"nobody","password":"whatever"}'

# Wrong password -> 401
curl -i -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"wrong"}'
```

## Building the container image

```sh
docker build -t authservice .
docker run --rm -p 8080:8080 authservice
```
