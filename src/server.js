'use strict';

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

app.disable('etag');

app.use(helmet({
  contentSecurityPolicy: false,
}));

app.use(express.json({ limit: '1mb' }));

/**
 * Origins
 *
 * Required Heroku config:
 *
 * CONNECT_PLUS_ALLOWED_ORIGINS=http://localhost:4200,https://partial.iwaconnectplus.org,https://www.iwaconnectplus.org,https://partial.iwaconnectplus.com,https://www.iwaconnectplus.com
 */
function parseOriginList(value) {
  return String(value || '')
    .split(',')
    .map((origin) => origin.trim().replace(/\/+$/, ''))
    .filter(Boolean);
}

const connectPlusAllowedOrigins = parseOriginList(
  process.env.CONNECT_PLUS_ALLOWED_ORIGINS
);

function cleanOrigin(origin) {
  return String(origin || '').trim().replace(/\/+$/, '');
}

function isAllowedOrigin(origin) {
  if (!origin) {
    return false;
  }

  return connectPlusAllowedOrigins.includes(cleanOrigin(origin));
}

/**
 * CORS
 */
const corsOptions = {
  origin(origin, callback) {
    if (!origin) {
      return callback(null, true);
    }

    if (isAllowedOrigin(origin)) {
      return callback(null, true);
    }

    return callback(new Error(`Origin not allowed: ${origin}`));
  },
  credentials: true,
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Cache-Control',
    'Pragma',
    'X-Proxy-Token',
    'X-Project',
    'X-Request-Id',
    'X-Request-Timestamp',
    'X-Request-Signature',
    'Origin',
    'Accept',
  ],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  optionsSuccessStatus: 204,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/**
 * CORS error handler.
 */
app.use((err, req, res, next) => {
  if (err && err.message && err.message.includes('Origin not allowed')) {
    const origin = req.headers.origin || '';

    console.error('CORS blocked:', {
      origin,
      allowedOrigins: connectPlusAllowedOrigins,
      method: req.method,
      path: req.originalUrl,
    });

    return res.status(403).json({
      error: 'Origin not allowed',
      origin,
      allowedOrigins: connectPlusAllowedOrigins,
    });
  }

  return next(err);
});

const rateLimitStore = new Map();

const BLOCKED_ROUTES = [
  { method: 'GET', path: '/event-admin/syncDB' },
  { method: 'GET', path: '/membership/syncDB' },
];

/**
 * Routes that must use the logged-in user's HLAuthToken.
 */
const CONNECT_PLUS_USER_TOKEN_ROUTES = [
  // User / profile
  { method: 'GET', path: '/user/me' },
  { method: 'POST', path: '/contact/updateprivacy' },
  { method: 'POST', path: '/contact/updatecontact' },
  { method: 'GET', path: '/contact/get-contact/:id' },
  { method: 'POST', path: '/contact/updateFMMember' },
  { method: 'GET', path: '/contact/get-sugg-fm' },
  { method: 'GET', path: '/contact/get-featured-by-week/:id' },
  { method: 'POST', path: '/contact/get-contactSearch' },

  // Search / people
  { method: 'POST', path: '/search' },
  { method: 'POST', path: '/search/suggest' },
  { method: 'GET', path: '/people-search/token' },
  { method: 'POST', path: '/people-search/query' },
  { method: 'GET', path: '/people-search/accounts' },
  { method: 'POST', path: '/people-search/account' },
  { method: 'POST', path: '/people-search/accounts-by-country' },
  { method: 'POST', path: '/people-search/next' },
  { method: 'POST', path: '/people-search/report' },
  { method: 'GET', path: '/people-search/getSearch' },
  { method: 'POST', path: '/people-search/getSearch' },

  // Groups / communities
  { method: 'GET', path: '/group/getMyGroups' },
  { method: 'GET', path: '/group/getMyGroup/:id' },
  { method: 'POST', path: '/group/getMyGroupsMembers' },
  { method: 'POST', path: '/group/getMyGroupsAdminDetails' },
  { method: 'POST', path: '/group/getMyGroupsSGAdminDetails' },
  { method: 'POST', path: '/group/updateGroup' },

  // Community meetings
  { method: 'GET', path: '/community-meetings' },
  { method: 'POST', path: '/community-meetings' },
  { method: 'PUT', path: '/community-meetings/:id' },
  { method: 'DELETE', path: '/community-meetings/:id' },

  // Friends / pals
  { method: 'GET', path: '/contact-palls/getMyPals' },
  { method: 'POST', path: '/contact-palls/getSuggMembers' },
  { method: 'GET', path: '/contact-palls/GetPendingReceivedFriendRequests' },
  { method: 'GET', path: '/contact-palls/GetMyFriends' },
  { method: 'POST', path: '/contact-palls' },
  { method: 'PUT', path: '/contact-palls/:id' },
  { method: 'DELETE', path: '/contact-palls/:id' },

  // Posts
  { method: 'POST', path: '/post/getPost' },
  { method: 'GET', path: '/post/TopTags' },
  { method: 'POST', path: '/post' },
  { method: 'PUT', path: '/post/:id' },
  { method: 'DELETE', path: '/post/:id' },
  { method: 'POST', path: '/post/getPostLike' },
  { method: 'POST', path: '/post/getLinkPreview' },
  { method: 'POST', path: '/post/getComments' },
  { method: 'POST', path: '/post-likes' },
  { method: 'DELETE', path: '/post-likes/:id' },
  { method: 'POST', path: '/post-comments' },
  { method: 'PUT', path: '/post-comments/:id' },
  { method: 'DELETE', path: '/post-comments/:id' },
  { method: 'POST', path: '/post-pin/create-pin' },
  { method: 'DELETE', path: '/post-pin/delete-pin/:id' },
  { method: 'GET', path: '/post-pin/get-pin/:id' },

  // Video stories
  { method: 'POST', path: '/video-story' },
  { method: 'POST', path: '/video-story/getVideoPost' },
  { method: 'DELETE', path: '/video-story/:id' },
  { method: 'POST', path: '/video-story/getComments' },
  { method: 'POST', path: '/video-story-likes' },
  { method: 'DELETE', path: '/video-story-likes/:id' },
  { method: 'POST', path: '/video-story-comments' },
  { method: 'PUT', path: '/video-story-comments/:id' },
  { method: 'DELETE', path: '/video-story-comments/:id' },

  // Polls
  { method: 'POST', path: '/poll' },
  { method: 'POST', path: '/poll/all' },
  { method: 'POST', path: '/poll/create' },
  { method: 'PUT', path: '/poll/:id' },
  { method: 'DELETE', path: '/poll/:id' },
  { method: 'POST', path: '/poll-votes' },

  // Newsletter / notifications
  { method: 'POST', path: '/c-newsletters' },
  { method: 'POST', path: '/c-newsletters/sendTestmail' },
  { method: 'POST', path: '/c-newsletters/get-notification' },
  { method: 'POST', path: '/c-newsletters/find' },
  { method: 'POST', path: '/c-newsletters/findAdmin' },
  { method: 'POST', path: '/c-newsletters/findSub' },
  { method: 'POST', path: '/c-newsletters/findOne' },
  { method: 'POST', path: '/c-newsletters/SendMailOnMeeting' },
  { method: 'POST', path: '/c-newsletters/SendMailOnMemberChange' },
  { method: 'GET', path: '/c-newsletters/newsletter-metrics/:id' },
  { method: 'GET', path: '/c-newsletters/emailletter-metrics/:id' },
  { method: 'GET', path: '/get-mynotification/:id' },
  { method: 'GET', path: '/update-mynotification/:id' },

  // Content library
  { method: 'POST', path: '/content-lib/get-autocomplete' },
  { method: 'POST', path: '/content-lib/get-autocomplete-author' },
  { method: 'POST', path: '/content-lib/get-autocomplete-tags' },
  { method: 'POST', path: '/content-lib/generatePresignedUrl' },
  { method: 'GET', path: '/content-lib/:id' },
  { method: 'GET', path: '/content-lib/getDocumentBase/:id' },
  { method: 'GET', path: '/content-lib/user-doc-rating/:id' },
  { method: 'POST', path: '/content-lib/search' },
  { method: 'POST', path: '/content-lib/get-types' },
  { method: 'GET', path: '/content-lib/get-event-info' },

  // Ratings
  { method: 'GET', path: '/cl-rating/:id' },
  { method: 'POST', path: '/cl-rating' },

  // Bookmarks
  { method: 'GET', path: '/cl-bookmark' },
  { method: 'GET', path: '/cl-bookmark/:id' },
  { method: 'POST', path: '/cl-bookmark' },
  { method: 'DELETE', path: '/cl-bookmark/:id' },

  // Blocks
  { method: 'GET', path: '/cl-block-url/:id' },
  { method: 'GET', path: '/cl-block-item/:id' },

  // Activity log
  { method: 'POST', path: '/activity-log/create' },
  { method: 'POST', path: '/activity-log/create-join' },

  // Community library / bookmarks
  { method: 'GET', path: '/community-libraries' },
  { method: 'POST', path: '/community-libraries' },
  { method: 'PUT', path: '/community-libraries/:id' },
  { method: 'DELETE', path: '/community-libraries/:id' },
  { method: 'GET', path: '/post-bookmarks' },
  { method: 'POST', path: '/post-bookmarks' },
  { method: 'DELETE', path: '/post-bookmarks/:id' },

  // Membership / renewal
  { method: 'POST', path: '/renewal/get-subscription' },
  { method: 'POST', path: '/renewal/get-one-subscription' },
  { method: 'POST', path: '/renewal/get-orders' },
  { method: 'POST', path: '/renewal/get-terms' },
  { method: 'POST', path: '/renewal/get-renew-path' },
  { method: 'POST', path: '/renewal/get-splan' },
  { method: 'POST', path: '/renewal/get-journal' },
];

/**
 * Routes that use short-lived proxy token and server-side CONNECT_PLUS_API_TOKEN.
 */
const CONNECT_PLUS_PROXY_TOKEN_ROUTES = [
  // Common lookup routes
  { method: 'GET', path: '/contact/get-dialcode' },
  { method: 'GET', path: '/country' },
  { method: 'GET', path: '/region' },
  { method: 'POST', path: '/tags' },
  { method: 'POST', path: '/authors' },

  // Event routes used inside Connect Plus / Join
  { method: 'POST', path: '/event/validateEmail' },
  { method: 'GET', path: '/event/getStateByCnty/:id' },
  { method: 'GET', path: '/event/country' },
  { method: 'GET', path: '/event/getEventCat' },
  { method: 'POST', path: '/event/getEvent' },
  { method: 'GET', path: '/event/GetMyWebinarRecordings/:id' },
  { method: 'POST', path: '/event-registration/states-by-country' },
  { method: 'GET', path: '/event/getEventGuestRegToken' },

  // Join / membership routes
  { method: 'POST', path: '/membership/validateEmail' },
  { method: 'POST', path: '/membership/insertUpdateMember' },
  { method: 'POST', path: '/membership/getPrice' },
  { method: 'GET', path: '/membership/getContactCol' },
  { method: 'GET', path: '/membership/getDoc/:type/:id' },
  { method: 'POST', path: '/membership/createMDiscountcode' },

  // Join / contact server-token routes
  { method: 'POST', path: '/contact/validate-user-email' },
  { method: 'POST', path: '/contact/create-member-sales-order' },
  { method: 'POST', path: '/contact/get-account-by-id' },
  { method: 'POST', path: '/contact/check-account-by-name' },
  { method: 'POST', path: '/contact/get-journals' },
  { method: 'POST', path: '/contact/get-sales-order-total' },
  { method: 'POST', path: '/contact/get-sales-order-invoice' },
  { method: 'POST', path: '/contact/get-membership-email-data' },
  { method: 'POST', path: '/contact/get-discount-ticket-types' },
  { method: 'GET', path: '/contact/get-source-codes' },
  { method: 'POST', path: '/contact/get-pricing-rules-by-ticket-type' },
  { method: 'POST', path: '/contact/get-price-rule-variables' },
  { method: 'POST', path: '/contact/create-source-code' },

  // Join / renewal server-token routes
  { method: 'POST', path: '/renewal/get-renewal-contact-data' },

  // Others
  { method: 'POST', path: '/others/sendEmailOther' },

  // Nomination
  { method: 'GET', path: '/nomination/getAllNomination/:id' },
  { method: 'POST', path: '/nomination/submit-form' },
  { method: 'POST', path: '/nomination/submit-form-fd' },
  { method: 'POST', path: '/nomination/submit-form-gm' },
  { method: 'POST', path: '/nomination/checkContactExitForm' },

  // Public CMS / content routes
  { method: 'GET', path: '/dashboard' },
  { method: 'GET', path: '/announcement' },
  { method: 'GET', path: '/announcements' },
  { method: 'GET', path: '/announcements/:id' },
  { method: 'GET', path: '/featured-articles' },
  { method: 'GET', path: '/faq-categories' },
  { method: 'GET', path: '/news' },
  { method: 'GET', path: '/news-feeds' },
  { method: 'GET', path: '/news-categories' },
  { method: 'GET', path: '/news-categories/:id' },
  { method: 'GET', path: '/learns' },
  { method: 'GET', path: '/learn-topics' },
  { method: 'POST', path: '/learn-blog/getAll' },
  { method: 'GET', path: '/learn-blog' },
  { method: 'POST', path: '/learn-video/getAll' },
  { method: 'GET', path: '/learn-video' },
  { method: 'GET', path: '/learn-infographics' },
  { method: 'GET', path: '/learn-courses' },
  { method: 'POST', path: '/content-lib/get-documents' },
  { method: 'GET', path: '/featured-publications' },
  { method: 'GET', path: '/most-read-articles' },
  { method: 'POST', path: '/featured-publications/most-read' },
  { method: 'GET', path: '/featured-books' },
];

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

function normalizePath(value) {
  if (!value) {
    return '/';
  }

  let path = String(value).trim();

  path = path.split('?')[0].split('#')[0];

  try {
    path = decodeURIComponent(path);
  } catch {
    // Keep original path if malformed URI is received.
  }

  path = path.replace(/\\/g, '/');
  path = path.replace(/\/{2,}/g, '/');

  if (!path.startsWith('/')) {
    path = `/${path}`;
  }

  path = path.replace(/\/+$/, '');

  return path || '/';
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

function isConnectPlusRequest(req) {
  const origin = cleanOrigin(req.headers.origin || '');
  const projectHeader = String(req.headers['x-project'] || '').trim();

  if (projectHeader && projectHeader !== 'connectPlus') {
    return false;
  }

  if (!isAllowedOrigin(origin)) {
    return false;
  }

  return true;
}

function createTokenBinding(req) {
  const origin = cleanOrigin(req.headers.origin || '');
  const userAgent = req.headers['user-agent'] || '';

  return crypto
    .createHash('sha256')
    .update(`${origin}|${userAgent}`)
    .digest('hex');
}

function isBrowserRequest(req) {
  const origin = cleanOrigin(req.headers.origin || '');
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

  if (referer && !referer.startsWith(`${origin}/`)) {
    return false;
  }

  if (
    secFetchSite &&
    !['same-origin', 'same-site', 'cross-site'].includes(secFetchSite)
  ) {
    return false;
  }

  if (
    secFetchMode &&
    !['cors', 'same-origin'].includes(secFetchMode)
  ) {
    return false;
  }

  if (secFetchDest && secFetchDest !== 'empty') {
    return false;
  }

  if (/postman|curl|insomnia|httpie|wget|python-requests/i.test(userAgent)) {
    return false;
  }

  return true;
}

function isUnsafePath(targetPath) {
  const cleanPath = normalizePath(targetPath).toLowerCase();

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

    if (cleanOrigin(decoded.origin) !== cleanOrigin(req.headers.origin || '')) {
      return { ok: false, status: 401, error: 'Proxy token origin mismatch' };
    }

    if (decoded.project !== 'connectPlus') {
      return { ok: false, status: 401, error: 'Proxy token project mismatch' };
    }

    if (decoded.binding !== createTokenBinding(req)) {
      return { ok: false, status: 401, error: 'Proxy token binding mismatch' };
    }

    return { ok: true, decoded };
  } catch {
    return { ok: false, status: 401, error: 'Invalid or expired proxy token' };
  }
}

function getConnectPlusServerToken(cleanTargetPath) {
  if (cleanTargetPath.toLowerCase().includes('webinar')) {
    return process.env.WEBINAR_API_TOKEN;
  }

  return process.env.CONNECT_PLUS_API_TOKEN;
}

function safeJoinUrl(baseUrl, targetPath) {
  const base = String(baseUrl || '').replace(/\/+$/, '');
  const path = targetPath.startsWith('/') ? targetPath : `/${targetPath}`;
  return `${base}${path}`;
}

function decodeJwtPayloadFromAuthorization(authorizationHeader) {
  try {
    if (!authorizationHeader || !authorizationHeader.startsWith('Bearer ')) {
      return null;
    }

    const tokenOnly = authorizationHeader.replace('Bearer ', '').trim();
    const payloadBase64 = tokenOnly.split('.')[1];

    if (!payloadBase64) {
      return null;
    }

    return JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
  } catch {
    return null;
  }
}

app.get('/health', (req, res) => {
  return res.json({
    ok: true,
    service: 'iwa-connectplus-express-proxy',
    allowedOrigins: connectPlusAllowedOrigins,
  });
});

app.get('/api/proxy-token', (req, res) => {
  const origin = cleanOrigin(req.headers.origin || '');
  const clientIp = getClientIp(req);

  if (!isConnectPlusRequest(req)) {
    return res.status(403).json({
      error: 'Connect Plus origin required',
      origin,
      allowedOrigins: connectPlusAllowedOrigins,
    });
  }

  if (!isBrowserRequest(req)) {
    return res.status(403).json({
      error: 'Browser request required',
      origin,
    });
  }

  if (isRateLimited(`proxy-token:${clientIp}:${origin}`, 30, 60 * 1000)) {
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
      project: 'connectPlus',
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

app.all('/api/proxy/*', async (req, res) => {
  try {
    const origin = cleanOrigin(req.headers.origin || '');
    const clientIp = getClientIp(req);

    if (!isConnectPlusRequest(req)) {
      return res.status(403).json({
        error: 'Connect Plus origin required',
        origin,
        allowedOrigins: connectPlusAllowedOrigins,
      });
    }

    if (!isBrowserRequest(req)) {
      return res.status(403).json({
        error: 'Browser request required',
        origin,
      });
    }

    const method = req.method.toUpperCase();
    const targetPath = req.originalUrl.replace('/api/proxy', '') || '/';
    const cleanTargetPath = normalizePath(targetPath);

    if (cleanTargetPath === '/user/me') {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }

    if (isUnsafePath(cleanTargetPath)) {
      return res.status(400).json({ error: 'Invalid or unsafe proxy path' });
    }

    if (matchesRoute(BLOCKED_ROUTES, method, cleanTargetPath)) {
      return res.status(403).json({ error: 'Proxy route blocked' });
    }

    const isUserTokenRoute = matchesRoute(
      CONNECT_PLUS_USER_TOKEN_ROUTES,
      method,
      cleanTargetPath
    );

    const isProxyTokenRoute = matchesRoute(
      CONNECT_PLUS_PROXY_TOKEN_ROUTES,
      method,
      cleanTargetPath
    );

    if (!isUserTokenRoute && !isProxyTokenRoute) {
      return res.status(403).json({
        error: 'Proxy route not allowed for Connect Plus',
        method,
        path: cleanTargetPath,
      });
    }

    if (isRateLimited(`proxy:${clientIp}:${origin}`, 300, 60 * 1000)) {
      return res.status(429).json({ error: 'Too many proxy requests' });
    }

    let authorizationHeader;
    let authType;

    if (isUserTokenRoute) {
      const userAuth = req.headers.authorization;

      if (!userAuth || !userAuth.startsWith('Bearer ')) {
        return res.status(401).json({
          error: 'User token required',
          path: cleanTargetPath,
        });
      }

      authorizationHeader = userAuth;
      authType = 'USER_TOKEN';
    } else if (isProxyTokenRoute) {
      const proxyCheck = verifyProxyToken(req);

      if (!proxyCheck.ok) {
        return res.status(proxyCheck.status).json({ error: proxyCheck.error });
      }

      const serverToken = getConnectPlusServerToken(cleanTargetPath);

      if (!serverToken) {
        return res.status(500).json({
          error: cleanTargetPath.toLowerCase().includes('webinar')
            ? 'Missing WEBINAR_API_TOKEN'
            : 'Missing CONNECT_PLUS_API_TOKEN',
        });
      }

      authorizationHeader = `Bearer ${serverToken}`;
      authType = 'SERVER_TOKEN';
    }

    const requestBodyString = JSON.stringify(req.body || {});
    const maxBodyBytes = Number(process.env.PROXY_MAX_BODY_BYTES || 100000);

    if (
      !['GET', 'HEAD'].includes(method) &&
      requestBodyString.length > maxBodyBytes
    ) {
      return res.status(413).json({ error: 'Request body too large' });
    }

    if (!process.env.STRAPI_URL) {
      return res.status(500).json({ error: 'Missing STRAPI_URL' });
    }

    const targetUrl = safeJoinUrl(process.env.STRAPI_URL, targetPath);

    const decodedUserPayload = authType === 'USER_TOKEN'
      ? decodeJwtPayloadFromAuthorization(authorizationHeader)
      : null;

    console.log('Connect Plus forwarding:', {
      method,
      cleanTargetPath,
      targetUrl,
      isUserTokenRoute,
      isProxyTokenRoute,
      hasAuthorization: !!authorizationHeader,
      authType,
      contactIdFromToken: decodedUserPayload?.id || null,
      tokenType: decodedUserPayload?.type || null,
    });

    const controller = new AbortController();
    const timeoutMs = Number(process.env.PROXY_TIMEOUT_MS || 100000);
    const timeout = setTimeout(() => controller.abort(), timeoutMs);

    let response;

    try {
      const targetHeaders = {
        Authorization: authorizationHeader,
        Accept: 'application/json',
        'Content-Type': 'application/json',
      };

      if (cleanTargetPath === '/user/me') {
        console.log('USER ME TOKEN DEBUG:', {
          contactIdFromToken: decodedUserPayload?.id || null,
          type: decodedUserPayload?.type || null,
          hasExp: !!decodedUserPayload?.exp,
          targetUrl,
        });
      }

      response = await fetch(targetUrl, {
        method,
        headers: targetHeaders,
        body: ['GET', 'HEAD'].includes(method) ? undefined : requestBodyString,
        signal: controller.signal,
      });
    } finally {
      clearTimeout(timeout);
    }

    const contentType = response.headers.get('content-type') || '';
    const responseText = await response.text();

    if (cleanTargetPath === '/user/me') {
      console.log('USER ME TARGET RESPONSE:', {
        status: response.status,
        contentType,
        responseText,
      });
    }

    res.status(response.status);

    if (cleanTargetPath === '/people-search/query') {
      res.setHeader('Content-Type', contentType || 'text/plain');
      return res.send(responseText);
    }

    if (contentType.includes('application/json')) {
      try {
        return res.json(responseText ? JSON.parse(responseText) : {});
      } catch {
        return res.status(502).json({
          error: 'Proxy target returned invalid JSON',
          targetStatus: response.status,
        });
      }
    }

    console.error('Proxy target returned non-JSON:', {
      targetUrl,
      status: response.status,
      contentType,
      preview: responseText.slice(0, 300),
    });

    return res.status(502).json({
      error: 'Proxy target did not return JSON',
      targetStatus: response.status,
      contentType,
      preview: responseText.slice(0, 300),
    });
  } catch (error) {
    if (error.name === 'AbortError') {
      return res.status(504).json({ error: 'Proxy request timed out' });
    }

    console.error('Connect Plus proxy error:', error);

    return res.status(500).json({
      error: 'Failed to connect to target API',
      message: error.message,
    });
  }
});

app.use((err, req, res, next) => {
  console.error('Unhandled middleware error:', err);

  return res.status(500).json({
    error: 'Internal middleware error',
    message: err.message,
  });
});

const port = process.env.PORT || 5000;

app.listen(port, () => {
  console.log(`IWA Connect Plus proxy running on port ${port}`);
});