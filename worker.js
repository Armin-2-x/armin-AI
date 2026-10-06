/**
 * Armin AI - Secure Cloudflare Worker Proxy
 *
 * Security model:
 * 1. GEMINI_API_KEY stored ONLY in Cloudflare Worker Secrets (never in repo).
 * 2. CORS restricted to a single origin (GitHub Pages) via ALLOWED_ORIGIN env var.
 * 3. Full SSE streaming from Gemini API (streamGenerateContent?alt=sse).
 * 4. In-memory rate limiting as a lightweight fallback (best-effort only).
 * 5. Strict input validation and structured error logging.
 *
 * Model lineup (per current Gemini API docs):
 * - gemini-3.8-flash        : newest stable, fast, recommended
 * - gemini-3.5-flash-lite   : lightest / cheapest
 * - gemini-3.5-flash        : balanced
 * - gemini-3.6-flash        : previous stable
 * - gemini-3.7-flash        : previous stable
 *
 * ⚠️ In-memory rate limiting in Cloudflare Workers is BEST-EFFORT.
 *    Isolates are ephemeral; counters reset on cold starts and are per-isolate,
 *    not global. For real abuse protection at scale, migrate to Durable Objects
 *    or KV.
 */

const DEFAULT_ALLOWED_ORIGIN = 'https://YOUR-USERNAME.github.io';
const DEFAULT_MODEL = 'gemini-3.8-flash';

const ALLOWED_MODELS = new Set([
  'gemini-3.8-flash',
  'gemini-3.7-flash',
  'gemini-3.6-flash',
  'gemini-3.5-flash',
  'gemini-3.5-flash-lite',
]);

const MAX_BODY_BYTES = 256 * 1024;
const MAX_MESSAGES = 50;
const MAX_TEXT_PER_PART = 20000;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_REQUESTS_PER_WINDOW = 20;
const UPSTREAM_TIMEOUT_MS = 60 * 1000;

const rateLimitMap = new Map();

function pruneRateLimitMap(now) {
  if (rateLimitMap.size < 5000) return;
  for (const [ip, data] of rateLimitMap) {
    if (now > data.resetTime) rateLimitMap.delete(ip);
  }
}

function isRateLimited(clientIp) {
  const now = Date.now();
  pruneRateLimitMap(now);

  const entry = rateLimitMap.get(clientIp);
  if (!entry || now > entry.resetTime) {
    rateLimitMap.set(clientIp, { count: 1, resetTime: now + RATE_LIMIT_WINDOW_MS });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_REQUESTS_PER_WINDOW;
}

function buildCorsHeaders(allowedOrigin) {
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

function jsonResponse(status, body, corsHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      ...corsHeaders,
    },
  });
}

function validateContents(contents) {
  if (!Array.isArray(contents) || contents.length === 0) {
    return 'پارامتر contents نامعتبر است یا خالی است.';
  }
  if (contents.length > MAX_MESSAGES) {
    return `تعداد پیام‌های گفتگو بیش از حد مجاز (${MAX_MESSAGES}) است.`;
  }
  for (const item of contents) {
    if (!item || typeof item !== 'object') return 'ساختار پیام نامعتبر است.';
    if (item.role !== 'user' && item.role !== 'model') {
      return 'نقش پیام باید user یا model باشد.';
    }
    if (!Array.isArray(item.parts) || item.parts.length === 0) {
      return 'هر پیام باید حداقل یک part داشته باشد.';
    }
    for (const part of item.parts) {
      if (!part || typeof part.text !== 'string') {
        return 'ساختار part نامعتبر است.';
      }
      if (part.text.length > MAX_TEXT_PER_PART) {
        return `متن هر پیام نباید از ${MAX_TEXT_PER_PART} کاراکتر بیشتر باشد.`;
      }
    }
  }
  return null;
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const requestOrigin = request.headers.get('Origin') || '';

    const allowedOrigin =
      (env.ALLOWED_ORIGIN && String(env.ALLOWED_ORIGIN).trim()) || DEFAULT_ALLOWED_ORIGIN;

    const corsHeaders = buildCorsHeaders(allowedOrigin);

    if (request.method === 'OPTIONS') {
      if (requestOrigin && requestOrigin !== allowedOrigin) {
        return new Response(null, { status: 403 });
      }
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/health')) {
      return jsonResponse(200, { status: 'ok', service: 'Armin AI Proxy' }, corsHeaders);
    }

    if (url.pathname !== '/api/chat') {
      return jsonResponse(404, { error: { message: 'Not Found' } }, corsHeaders);
    }
    if (request.method !== 'POST') {
      return jsonResponse(405, { error: { message: 'Method Not Allowed' } }, corsHeaders);
    }

    if (requestOrigin && requestOrigin !== allowedOrigin) {
      console.error('[Armin AI] Blocked request from disallowed origin:', requestOrigin);
      return jsonResponse(403, { error: { message: 'Origin not allowed.' } }, corsHeaders);
    }

    const apiKey = env.GEMINI_API_KEY;
    if (!apiKey) {
      console.error('[Armin AI] GEMINI_API_KEY is not configured in Worker secrets.');
      return jsonResponse(
        500,
        { error: { message: 'کلید سرویس هوش مصنوعی در تنظیمات سرور ثبت نشده است.' } },
        corsHeaders
      );
    }

    const clientIp = request.headers.get('cf-connecting-ip') || 'unknown';
    if (isRateLimited(clientIp)) {
      console.error(`[Armin AI] Rate limit hit for IP: ${clientIp}`);
      return jsonResponse(
        429,
        { error: { message: 'تعداد درخواست‌های شما بیش از حد مجاز است. لطفاً یک دقیقه دیگر تلاش کنید.' } },
        corsHeaders
      );
    }

    const contentLength = Number(request.headers.get('content-length') || 0);
    if (contentLength && contentLength > MAX_BODY_BYTES) {
      return jsonResponse(
        413,
        { error: { message: 'حجم درخواست بیش از حد مجاز است.' } },
        corsHeaders
      );
    }

    let body;
    try {
      body = await request.json();
    } catch (err) {
      console.error('[Armin AI] Failed to parse request JSON:', err);
      return jsonResponse(400, { error: { message: 'بدنه درخواست JSON معتبر نیست.' } }, corsHeaders);
    }

    const requestedModel = typeof body.model === 'string' ? body.model : DEFAULT_MODEL;
    if (!ALLOWED_MODELS.has(requestedModel)) {
      console.error('[Armin AI] Rejected disallowed model:', requestedModel);
      return jsonResponse(
        400,
        { error: { message: 'مدل انتخاب‌شده مجاز نیست.' } },
        corsHeaders
      );
    }

    const contents = body.contents;
    const validationError = validateContents(contents);
    if (validationError) {
      return jsonResponse(400, { error: { message: validationError } }, corsHeaders);
    }

    const systemInstruction =
      typeof body.systemInstruction === 'string' ? body.systemInstruction : '';
    const stream = body.stream !== false;

    const geminiAction = stream ? 'streamGenerateContent?alt=sse' : 'generateContent';
    const geminiUrl = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(requestedModel)}:${geminiAction}&key=${apiKey}`;

    const geminiPayload = { contents };
    if (systemInstruction) {
      geminiPayload.systemInstruction = { parts: [{ text: systemInstruction }] };
    }

    let geminiResponse;
    try {
      geminiResponse = await fetch(geminiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(geminiPayload),
        signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
      });
    } catch (err) {
      console.error('[Armin AI] Upstream fetch failed:', err?.name || err?.message || err);
      const isTimeout = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      return jsonResponse(
        isTimeout ? 504 : 502,
        {
          error: {
            message: isTimeout
              ? 'پاسخی از سرور در زمان مجاز دریافت نشد. لطفاً دوباره تلاش کنید.'
              : 'خطا در ارتباط با سرور هوش مصنوعی.',
          },
        },
        corsHeaders
      );
    }

    if (!geminiResponse.ok) {
      let errorBody = '';
      try {
        errorBody = await geminiResponse.text();
      } catch (_) {
        /* ignore */
      }
      console.error(
        `[Armin AI] Upstream responded with ${geminiResponse.status}:`,
        errorBody.slice(0, 500)
      );
      return new Response(
        errorBody || JSON.stringify({ error: { message: 'خطای نامشخص از سرور' } }),
        {
          status: geminiResponse.status,
          headers: {
            'Content-Type': 'application/json; charset=utf-8',
            ...corsHeaders,
          },
        }
      );
    }

    if (stream) {
      return new Response(geminiResponse.body, {
        status: 200,
        headers: {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache, no-transform',
          'Connection': 'keep-alive',
          'X-Accel-Buffering': 'no',
          ...corsHeaders,
        },
      });
    }

    try {
      const data = await geminiResponse.json();
      return jsonResponse(200, data, corsHeaders);
    } catch (err) {
      console.error('[Armin AI] Failed to parse upstream JSON response:', err);
      return jsonResponse(502, { error: { message: 'پاسخ سرور قابل تجزیه نبود.' } }, corsHeaders);
    }
  },
};