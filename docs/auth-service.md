# authservice

A mock authentication service written in Node.js. It validates logins against
the sample accounts in [`src/authservice/data/users.json`](/src/authservice/data/users.json)
— there is no database and no external dependency.

> **This service is a mock.** Passwords are stored in plaintext and the returned
> token is an opaque, unsigned string. Do not use it as-is in production.

## Endpoints

### `POST /login`

```sh
curl -i -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password123"}'
```

```json
{
  "token": "mock-token-YWxpY2U6MTc2MjAwMDAwMDAwMA",
  "user": {
    "username": "alice",
    "name": "Alice Nguyen",
    "email": "alice@example.com"
  }
}
```

| Status | When |
| --- | --- |
| `200` | The credentials match a sample account |
| `400` | The body is malformed or `username`/`password` is missing |
| `401` | The user does not exist, or the password is wrong |

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

## Deploying

The service is part of the default manifests, so `skaffold run` (or
`kubectl apply -k kubernetes-manifests`) deploys it as `authservice` on port
`8080` inside the cluster:

```
authservice.<namespace>.svc.cluster.local:8080
```

For Helm:

```sh
helm install onlineboutique helm-chart
# Disable it with: --set authService.create=false
```
