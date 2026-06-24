'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const path = require('path');

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));

const allowedOrigins = (process.env.FRONTEND_ALLOWED_ORIGINS || '')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    /**
     * Keep this flexible for CORS preflight/health,
     * but actual proxy endpoints are protected by isBrowserRequest().
     */
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error('Origin not allowed'));
  },
  credentials: true,
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-Proxy-Token',
    'X-Event-Guest-Token',
    'X-Request-Id',
    'X-Request-Timestamp',
    'X-Request-Signature',
    'Origin',
    'Accept',
  ],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
}));

const rateLimitStore = new Map();

const BLOCKED_ROUTES = [
  { method: 'GET', path: '/event-admin/syncDB' },
];

const USER_TOKEN_ROUTES = [
  { method: 'GET', path: '/user/me' },
  { method: 'POST', path: '/event-registration/generate-discount-code' },
  { method: 'POST', path: '/event-registration/generate-discount-code-job-status' },
  { method: 'POST', path: '/event-registration/badge-attendees' },
  { method: 'POST', path: '/event-registration/update-attendee-checkin' },
];

const PROXY_TOKEN_ROUTES = [
  { method: 'GET', path: '/contact/get-dialcode' },
  { method: 'DELETE', path: '/event-attendee/delete-ticket/:key' },
  { method: 'GET', path: '/others/get-wdce2025-sessions' },
{ method: 'GET', path: '/others/get-wdce2025-abstract/:id' },
{ method: 'GET', path: '/others/search-wdce2025-abstract/:key' },
{ method: 'POST', path: '/others/createOrUpdateAbstract' },
{ method: 'POST', path: '/others/updateFiletoSession' },
{ method: 'POST', path: '/others/broadcast' },
{ method: 'GET', path: '/others/broadcast/stream' },
  { method: 'POST', path: '/event-registration/ticket-types' },
  { method: 'POST', path: '/event-registration/states-by-country' },
  { method: 'POST', path: '/event-registration/tickets' },
  { method: 'POST', path: '/event-registration/price-rules' },
  { method: 'POST', path: '/event-registration/check-discount-code' },
  { method: 'POST', path: '/event-registration/check-gala-dinner' },

  { method: 'GET', path: '/event-attendee/get-all-events' },
  { method: 'GET', path: '/event-attendee/get-basic-event-data/:key' },
  { method: 'GET', path: '/event-attendee/get-venue-data/:key' },
  { method: 'GET', path: '/event-attendee/get-country' },
  { method: 'GET', path: '/event-attendee/get-guest-token' },
  { method: 'GET', path: '/event-attendee/get-sub-event/:key' },

  { method: 'POST', path: '/event-registration/order-lines-by-email' },
  { method: 'POST', path: '/event-registration/check-already-paid' },
  { method: 'POST', path: '/event-registration/getUserByEmail' },

  { method: 'POST', path: '/event-attendee/validate-email' },
  { method: 'POST', path: '/event-attendee/send-email' },
  { method: 'POST', path: '/event/activity-log' },
  { method: 'POST', path: '/event-attendee/get-order-summary' },
  { method: 'POST', path: '/event-attendee/update-form-data' },
  { method: 'GET', path: '/event-attendee/get-form-data/:id' },
  {method:'POST',path:'/shocklogic-sync/shocklogic-abstracts'},

  { method: 'POST', path: '/event-registration/sales-order' },
  { method: 'POST', path: '/event-registration/sales-order-lines' },
  { method: 'POST', path: '/event-registration/receipt' },
  { method: 'POST', path: '/event-registration/draft-count' },
  { method: 'POST', path: '/event-registration/delete-draft-order' },
  { method: 'POST', path: '/event-registration/update-payment-method' },
  { method: 'POST', path: '/event-registration/order-data' },
  { method: 'POST', path: '/event-registration/add-to-waitlist' },
  { method: 'POST', path: '/event-registration/create-sales-order-with-validation' },
  { method: 'POST', path: '/event-registration/sales-order-payment-details' },

  { method: 'POST', path: '/event-attendee/insert-attendee' },
  { method: 'POST', path: '/event-attendee/insert-sub-event-attendee' },
  { method: 'POST', path: '/event-attendee/insert-single-attendee' },

  { method: 'POST', path: '/event-attendee/apply-discount-code' },
  { method: 'POST', path: '/event-attendee/prepare-additional-ticket' },
  { method: 'POST', path: '/event-attendee/get-attendee-by-sales-order-id' },
];

const EVENT_GUEST_TOKEN_ROUTES = [];

function getClientIp(req) {
  return (
    req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
    req.socket?.remoteAddress ||
    'unknown'
  );
}

function isRateLimited(key, maxRequests, windowMs) {
  const now = Date.now();
  const current = rateLimitStore.get(key);

  if (!current || current.resetAt <= now) {
    rateLimitStore.set(key, {
      count: 1,
      resetAt: now + windowMs,
    });
    return false;
  }

  current.count += 1;
  rateLimitStore.set(key, current);

  return current.count > maxRequests;
}

setInterval(() => {
  const now = Date.now();

  for (const [key, value] of rateLimitStore.entries()) {
    if (value.resetAt <= now) {
      rateLimitStore.delete(key);
    }
  }
}, 5 * 60 * 1000).unref();

function normalizePath(path) {
  return path.split('?')[0].replace(/\/+$/, '') || '/';
}

function routeToRegex(routePath) {
  const withoutTrailingSlash = routePath.replace(/\/+$/, '') || '/';

  const regexText = withoutTrailingSlash
    .split('/')
    .map((part) => {
      if (part.startsWith(':')) {
        return '[^/]+';
      }

      return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    })
    .join('/');

  return new RegExp(`^${regexText}$`);
}

function matchesRoute(routeList, method, path) {
  const cleanPath = normalizePath(path);
  const cleanMethod = method.toUpperCase();

  return routeList.some((route) => (
    route.method.toUpperCase() === cleanMethod &&
    routeToRegex(route.path).test(cleanPath)
  ));
}

function createTokenBinding(req) {
  const origin = req.headers.origin || '';
  const userAgent = req.headers['user-agent'] || '';

  return crypto
    .createHash('sha256')
    .update(`${origin}|${userAgent}`)
    .digest('hex');
}

function isAllowedOrigin(origin) {
  return !!origin && allowedOrigins.includes(origin);
}

/**
 * Blocks normal Postman/curl/direct API calls.
 *
 * Important:
 * A determined attacker can still spoof browser headers.
 * This is not a replacement for token expiry, server-side auth,
 * route allowlisting, and permission checks.
 */
function isBrowserRequest(req) {
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';
  const secFetchSite = req.headers['sec-fetch-site'];
  const secFetchMode = req.headers['sec-fetch-mode'];
  const secFetchDest = req.headers['sec-fetch-dest'];
  const userAgent = req.headers['user-agent'] || '';

  if (!origin) {
    return false;
  }

  if (!isAllowedOrigin(origin)) {
    return false;
  }

  if (!referer || !referer.startsWith(`${origin}/`)) {
    return false;
  }

  /**
   * Browser fetch/XHR sends Sec-Fetch-* headers.
   * Postman/curl usually do not send these unless manually spoofed.
   */
  if (!secFetchSite || !secFetchMode || !secFetchDest) {
    return false;
  }

  if (!['same-origin', 'same-site', 'cross-site'].includes(secFetchSite)) {
    return false;
  }

  /**
   * Angular HttpClient/fetch usually sends mode "cors".
   */
  if (!['cors', 'same-origin'].includes(secFetchMode)) {
    return false;
  }

  /**
   * XHR/fetch usually sends dest "empty".
   */
  if (secFetchDest !== 'empty') {
    return false;
  }

  /**
   * Basic block for common API clients.
   */
  if (/postman|curl|insomnia|httpie|wget|python-requests|axios/i.test(userAgent)) {
    return false;
  }

  return true;
}

function isUnsafePath(targetPath) {
  const cleanPath = targetPath.toLowerCase();

  return (
    cleanPath.includes('..') ||
    cleanPath.includes('\\') ||
    cleanPath.startsWith('//') ||
    cleanPath.includes('/admin') ||
    cleanPath.includes('/content-manager') ||
    cleanPath.includes('/content-type-builder') ||
    cleanPath.includes('/users-permissions') ||
    cleanPath.includes('/roles') ||
    cleanPath.includes('/permissions') ||
    cleanPath.includes('/settings') ||
    cleanPath.includes('/config')
  );
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || '').trim());
}

function isSafeEventKey(eventKey) {
  return /^[a-zA-Z0-9_-]{1,100}$/.test(String(eventKey || '').trim());
}

function getBodyEmail(req) {
  return (
    req.body?.email ||
    req.body?.Email ||
    req.body?.attendeeEmail ||
    req.body?.AttendeeEmail ||
    req.body?.primaryEmail ||
    req.body?.PrimaryEmail ||
    req.body?.Email_Address__c ||
    req.body?.primaryContact?.email ||
    req.body?.primaryContact?.Email ||
    req.body?.data?.email ||
    req.body?.data?.Email ||
    req.query?.email ||
    ''
  );
}

function getBodyEventKey(req) {
  return (
    req.body?.eventKey ||
    req.body?.EventKey ||
    req.body?.key ||
    req.body?.Key ||
    req.body?.event_key ||
    req.body?.EventApi__Event_Key__c ||
    req.body?.event?.eventKey ||
    req.body?.eventData?.eventKey ||
    req.body?.data?.eventKey ||
    req.query?.eventKey ||
    req.query?.key ||
    ''
  );
}

function verifyProxyToken(req) {
  const proxyToken = req.headers['x-proxy-token'];
  const secret = process.env.PROXY_JWT_SECRET;

  if (!secret) {
    return { ok: false, status: 500, error: 'Missing PROXY_JWT_SECRET' };
  }

  if (!proxyToken) {
    return { ok: false, status: 401, error: 'Proxy token required' };
  }

  try {
    const decoded = jwt.verify(proxyToken, secret, {
      issuer: 'iwa-connectplus',
      audience: 'iwa-proxy',
    });

    if (decoded.type !== 'anonymous_proxy') {
      return { ok: false, status: 401, error: 'Invalid proxy token type' };
    }

    if (decoded.origin !== (req.headers.origin || '')) {
      return { ok: false, status: 401, error: 'Proxy token origin mismatch' };
    }

    if (decoded.binding !== createTokenBinding(req)) {
      return { ok: false, status: 401, error: 'Proxy token binding mismatch' };
    }

    return { ok: true, decoded };
  } catch {
    return { ok: false, status: 401, error: 'Invalid or expired proxy token' };
  }
}

function createEventGuestToken({ eventKey, email, origin }) {
  const secret = process.env.EVENT_GUEST_JWT_SECRET || process.env.PROXY_JWT_SECRET;
  const expiresIn = Number(process.env.EVENT_GUEST_JWT_EXPIRES_SECONDS || 900);

  if (!secret) {
    throw new Error('Missing EVENT_GUEST_JWT_SECRET or PROXY_JWT_SECRET');
  }

  const token = jwt.sign(
    {
      type: 'event_guest',
      eventKey: String(eventKey).trim(),
      email: String(email).trim().toLowerCase(),
      origin,
    },
    secret,
    {
      expiresIn,
      issuer: 'iwa-connectplus',
      audience: 'iwa-event-guest',
    }
  );

  return {
    token,
    expiresIn,
    expiresAt: Date.now() + expiresIn * 1000,
  };
}

function verifyEventGuestToken(req, expectedData) {
  const secret = process.env.EVENT_GUEST_JWT_SECRET || process.env.PROXY_JWT_SECRET;
  const token = req.headers['x-event-guest-token'];

  if (!secret) {
    return { ok: false, status: 500, error: 'Missing EVENT_GUEST_JWT_SECRET or PROXY_JWT_SECRET' };
  }

  if (!token) {
    return { ok: false, status: 401, error: 'Event guest token required' };
  }

  try {
    const decoded = jwt.verify(token, secret, {
      issuer: 'iwa-connectplus',
      audience: 'iwa-event-guest',
    });

    if (decoded.type !== 'event_guest') {
      return { ok: false, status: 401, error: 'Invalid event guest token type' };
    }

    if (decoded.origin !== (req.headers.origin || '')) {
      return { ok: false, status: 401, error: 'Event guest token origin mismatch' };
    }

    if (decoded.eventKey !== String(expectedData.eventKey).trim()) {
      return { ok: false, status: 403, error: 'Event guest token event mismatch' };
    }

    if (decoded.email !== String(expectedData.email).trim().toLowerCase()) {
      return { ok: false, status: 403, error: 'Event guest token email mismatch' };
    }

    return { ok: true, decoded };
  } catch {
    return { ok: false, status: 401, error: 'Invalid or expired event guest token' };
  }
}

function safeJoinUrl(baseUrl, targetPath) {
  const base = baseUrl.replace(/\/+$/, '');
  const path = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;
  return `${base}${path}`;
}

function getServerTokenForPath(cleanTargetPath) {
  if (cleanTargetPath.toLowerCase().includes('webinar')) {
    return process.env.WEBINAR_API_TOKEN;
  }

  return process.env.EVENT_API_TOKEN;
}

app.get('/health', (req, res) => {
  return res.json({ ok: true, service: 'iwa-express-proxy' });
});

app.get('/api/proxy-token', (req, res) => {
  const origin = req.headers.origin || '';
  const clientIp = getClientIp(req);

  if (!isBrowserRequest(req)) {
    return res.status(403).json({ error: 'Browser request required' });
  }

  if (isRateLimited(`proxy-token:${clientIp}:${origin}`, 10, 60 * 1000)) {
    return res.status(429).json({ error: 'Too many proxy token requests' });
  }

  if (!process.env.PROXY_JWT_SECRET) {
    return res.status(500).json({ error: 'Missing PROXY_JWT_SECRET' });
  }

  const expiresIn = Number(process.env.PROXY_JWT_EXPIRES_SECONDS || 120);

  const token = jwt.sign(
    {
      type: 'anonymous_proxy',
      origin,
      binding: createTokenBinding(req),
    },
    process.env.PROXY_JWT_SECRET,
    {
      expiresIn,
      issuer: 'iwa-connectplus',
      audience: 'iwa-proxy',
    }
  );

  return res.json({
    token,
    expiresIn,
    expiresAt: Date.now() + expiresIn * 1000,
  });
});

app.get('/api/event-guest-token', (req, res) => {
  const origin = req.headers.origin || '';
  const clientIp = getClientIp(req);

  if (!isBrowserRequest(req)) {
    return res.status(403).json({ error: 'Browser request required' });
  }

  if (isRateLimited(`event-guest-token:${clientIp}:${origin}`, 10, 60 * 1000)) {
    return res.status(429).json({ error: 'Too many event guest token requests' });
  }

  const proxyCheck = verifyProxyToken(req);

  if (!proxyCheck.ok) {
    return res.status(proxyCheck.status).json({ error: proxyCheck.error });
  }

  const eventKey = String(req.query.eventKey || '').trim();
  const email = String(req.query.email || '').trim().toLowerCase();

  if (!isSafeEventKey(eventKey)) {
    return res.status(400).json({ error: 'Invalid event key' });
  }

  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email' });
  }

  return res.json(createEventGuestToken({
    eventKey,
    email,
    origin,
  }));
});

app.all('/api/proxy/*', async (req, res) => {
  try {
    const origin = req.headers.origin || '';
    const clientIp = getClientIp(req);

    if (!isBrowserRequest(req)) {
      return res.status(403).json({ error: 'Browser request required' });
    }

    const method = req.method.toUpperCase();
    const targetPath = req.originalUrl.replace('/api/proxy', '') || '/';
    const cleanTargetPath = normalizePath(targetPath);

    if (isUnsafePath(cleanTargetPath)) {
      return res.status(400).json({ error: 'Invalid or unsafe proxy path' });
    }

    if (matchesRoute(BLOCKED_ROUTES, method, cleanTargetPath)) {
      return res.status(403).json({ error: 'Proxy route blocked' });
    }

    const isUserTokenRoute = matchesRoute(USER_TOKEN_ROUTES, method, cleanTargetPath);
    const isProxyTokenRoute = matchesRoute(PROXY_TOKEN_ROUTES, method, cleanTargetPath);
    const isEventGuestTokenRoute = matchesRoute(EVENT_GUEST_TOKEN_ROUTES, method, cleanTargetPath);

    if (!isUserTokenRoute && !isProxyTokenRoute && !isEventGuestTokenRoute) {
      return res.status(403).json({ error: 'Proxy route not allowed' });
    }

    if (isRateLimited(`proxy:${clientIp}:${origin}`, 120, 60 * 1000)) {
      return res.status(429).json({ error: 'Too many proxy requests' });
    }

    let authorizationHeader;

    if (isUserTokenRoute) {
      const userAuth = req.headers.authorization;

      if (!userAuth || !userAuth.startsWith('Bearer ')) {
        return res.status(401).json({ error: 'User token required' });
      }

      authorizationHeader = userAuth;
    }

    if (isProxyTokenRoute) {
      const proxyCheck = verifyProxyToken(req);

      if (!proxyCheck.ok) {
        return res.status(proxyCheck.status).json({ error: proxyCheck.error });
      }

      const serverToken = getServerTokenForPath(cleanTargetPath);

      if (!serverToken) {
        return res.status(500).json({ error: 'Missing server API token' });
      }

      authorizationHeader = `Bearer ${serverToken}`;
    }

    if (isEventGuestTokenRoute) {
      const userAuth = req.headers.authorization;

      if (userAuth && userAuth.startsWith('Bearer ')) {
        authorizationHeader = userAuth;
      } else {
        const proxyCheck = verifyProxyToken(req);

        if (!proxyCheck.ok) {
          return res.status(proxyCheck.status).json({ error: proxyCheck.error });
        }

        const eventKey = getBodyEventKey(req);
        const email = getBodyEmail(req);

        if (!isSafeEventKey(eventKey)) {
          return res.status(400).json({ error: 'Invalid or missing event key' });
        }

        if (!isValidEmail(email)) {
          return res.status(400).json({ error: 'Invalid or missing email' });
        }

        const guestCheck = verifyEventGuestToken(req, {
          eventKey,
          email,
        });

        if (!guestCheck.ok) {
          return res.status(guestCheck.status).json({ error: guestCheck.error });
        }

        const serverToken = getServerTokenForPath(cleanTargetPath);

        if (!serverToken) {
          return res.status(500).json({ error: 'Missing server API token' });
        }

        authorizationHeader = `Bearer ${serverToken}`;
      }
    }

    const requestBodyString = JSON.stringify(req.body || {});
    const maxBodyBytes = Number(process.env.PROXY_MAX_BODY_BYTES || 100000);

    if (!['GET', 'HEAD'].includes(method) && requestBodyString.length > maxBodyBytes) {
      return res.status(413).json({ error: 'Request body too large' });
    }

    if (!process.env.STRAPI_URL) {
      return res.status(500).json({ error: 'Missing STRAPI_URL' });
    }

    const targetUrl = safeJoinUrl(process.env.STRAPI_URL, targetPath);

    const controller = new AbortController();
    const timeoutMs = Number(process.env.PROXY_TIMEOUT_MS || 100000);
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let response;

    try {
      response = await fetch(targetUrl, {
        method,
        headers: {
          Authorization: authorizationHeader,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: ['GET', 'HEAD'].includes(method) ? undefined : requestBodyString,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    const contentType = response.headers.get('content-type') || '';
    const responseText = await response.text();

    res.status(response.status);

    if (contentType.includes('application/json')) {
      return res.json(responseText ? JSON.parse(responseText) : {});
    }

    return res.status(502).json({ error: 'Proxy target did not return JSON' });
  } catch (error) {
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'Proxy request timed out' });
    }

    console.error('Express proxy error:', error);
    return res.status(500).json({ error: 'Failed to connect to target API' });
  }
});

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`IWA Express proxy running on port ${port}`);
});