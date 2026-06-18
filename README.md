# IWA Express Proxy Middleware

This project is a separate Express middleware proxy for the IWA event registration frontend.

The frontend calls this service, and this service forwards approved requests to Strapi/Event APIs using server-side tokens stored in environment variables.

## What this does

- Keeps `EVENT_API_TOKEN`, `WEBINAR_API_TOKEN`, and other server tokens out of Angular.
- Provides `/api/proxy-token` for short-lived anonymous proxy access.
- Provides `/api/event-guest-token` for guest registration flows.
- Separates routes into blocked, member-only, public/reference, and guest-registration categories.
- Blocks unknown proxy routes by default.
- Applies origin checks, rate limits, body-size checks, and forwarding timeout.

## Install

```bash
npm install
```

## Configure

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Then update the values.

## Run locally

```bash
npm run dev
```

or:

```bash
npm start
```

## Angular environment example

```ts
export const environment = {
  production: false,
  BaseApiUrl: 'http://localhost:5000/api/proxy',
  ProxyTokenUrl: 'http://localhost:5000/api/proxy-token',
  EventGuestTokenUrl: 'http://localhost:5000/api/event-guest-token',
};
```

## Example endpoints

```txt
GET  /api/proxy-token
GET  /api/event-guest-token?eventKey=wwce2026&email=guest@example.com
POST /api/proxy/event-attendee/insert-attendee
POST /api/proxy/event-attendee/get-order-summary
```

## Deployment notes

Set all `.env` values in your hosting provider, such as Heroku Config Vars.

Recommended production variables:

```txt
FRONTEND_ALLOWED_ORIGINS
STRAPI_URL
EVENT_API_TOKEN
WEBINAR_API_TOKEN
PROXY_JWT_SECRET
EVENT_GUEST_JWT_SECRET
PROXY_MAX_BODY_BYTES
PROXY_TIMEOUT_MS
```
