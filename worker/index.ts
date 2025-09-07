export interface Env {
  ASSETS: Fetcher;
  ALLOW_ORIGIN?: string;
  MC_API_KEY?: string;
  DKIM_DOMAIN?: string;
  DKIM_SELECTOR?: string;
  DKIM_PRIVATE_KEY?: string;
  EMAIL_CONTACT?: string;
  EMAIL_REGISTRATION?: string;
  EMAIL_WORKWITHUS?: string;
  FROM_EMAIL?: string;
  JWT_SECRET?: string;
  DB?: D1Database;
  BIBLIOTECA_R2?: R2Bucket;
  CONFIG?: KVNamespace;
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    console.log('[fetch] incoming request', { method: request.method, path: url.pathname });
    await hydrateEnvFromKV(env);

    // CORS preflight for API route
    if (request.method === 'OPTIONS' && url.pathname.startsWith('/api/')) {
      return corsPreflight(env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/login' }).test(url)) {
      return await bibliotecaLogin(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/register' }).test(url)) {
      return await bibliotecaRegister(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/logout' }).test(url)) {
      return await bibliotecaLogout(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/password/forgot' }).test(url)) {
      return await bibliotecaPasswordForgot(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/password/reset' }).test(url)) {
      return await bibliotecaPasswordReset(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/biblioteca/verify-email' }).test(url)) {
      return await bibliotecaVerifyEmail(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/form/contato' }).test(url)) {
      return await sendContactEmail(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/form/cadastro' }).test(url)) {
      return await sendRegistrationEmail(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/form/trabalhe-conosco' }).test(url)) {
      return await sendWorkWithUsEmail(request, env);
    }

    if (request.method === 'POST' && new URLPattern({ pathname: '/api/form/newsletter' }).test(url)) {
      return await sendNewsletterEmail(request, env);
    }

    // Biblioteca protected download(s): stream any file from R2 using wildcard path
    if (request.method === 'GET' && new URLPattern({ pathname: '/biblioteca/download/*' }).test(url)) {
      return await bibliotecaDownload(request, env);
    }

    if (
      request.method === 'GET'
      && url.pathname.startsWith('/biblioteca')
      && !url.pathname.startsWith('/biblioteca/login')
      && !url.pathname.startsWith('/biblioteca/registro')
      && !url.pathname.startsWith('/biblioteca/recuperar-senha')
      && !url.pathname.startsWith('/biblioteca/definir-senha')
      && !url.pathname.startsWith('/biblioteca/verificar-email')
    ) {
      const token = readJwtFromCookie(request);
      const payload = token ? await verifyJWT(token, env.JWT_SECRET || 'dev-secret') : null;
      if (!payload) {
        const to = new URL('/biblioteca/login', url);
        return Response.redirect(to.toString(), 302);
      }
    }

    // Serve static assets; on 404, return our custom 404 page
    const assetRes = await env.ASSETS.fetch(request);
    if (assetRes.status === 404 && request.method === 'GET' && !url.pathname.startsWith('/api/')) {
      const notFoundUrl = new URL('/404.html', url);
      const nfReq = new Request(notFoundUrl.toString(), request);
      const nfRes = await env.ASSETS.fetch(nfReq);
      // Use body and headers from the file but force 404 status
      return new Response(nfRes.body, { status: 404, headers: nfRes.headers });
    }

    return assetRes;
  }
} satisfies ExportedHandler<Env>;

async function bibliotecaPasswordForgot(request: Request, env: Env): Promise<Response> {
  try {
    const data = await readBodyFlexible(request);
    const email = (data.email || '').toString().trim().toLowerCase().slice(0, 100);
    if (!email) return json({ success: true }, 200, env); // do not leak
    if (!env.DB) return json({ success: true }, 200, env);

    // Check user exists and get id
    const user = await env.DB
      .prepare('SELECT id, email FROM users WHERE email = ?1 LIMIT 1')
      .bind(email)
      .first<{ id: string; email: string }>();
    if (!user) return json({ success: true }, 200, env); // same behavior

    // Create token valid for 1 hour
    const rand = crypto.getRandomValues(new Uint8Array(32));
    const token = base64urlEncode(rand);
    const created = new Date();
    const expires = new Date(created.getTime() + 60 * 60 * 1000);
    const id = generateUlid();
    await env.DB
      .prepare('INSERT INTO password_resets (id, user_id, token, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(id, user.id, token, created.toISOString(), expires.toISOString())
      .run();

    // Build link
    const base = new URL(request.url);
    base.pathname = '/biblioteca/definir-senha';
    base.search = `token=${token}`;
    const resetUrl = base.toString();

    // Send email to user
    const fromEmail = (env.FROM_EMAIL || '').toString().trim();
    if (!fromEmail) return json({ success: true }, 200, env);
    const label12 = 'FONT-SIZE:12PX;';
    const html = [`<b style='${label12}'>Olá,</b><br/>`,`Para redefinir sua senha, clique no link abaixo:<br/>`,`<a href="${resetUrl}">${resetUrl}</a><br/><br/>`,`Se você não solicitou, ignore este e-mail.`].join('');
    const text = `Olá,\nPara redefinir sua senha, acesse: ${resetUrl}\n\nSe você não solicitou, ignore este e-mail.`;
    const mail: MailChannelsRequest = {
      personalizations: [{ to: [{ email }] }],
      from: { email: fromEmail, name: 'Dérig' },
      subject: '[Biblioteca] Redefinição de senha',
      content: [
        { type: 'text/plain', value: text },
        { type: 'text/html', value: html }
      ]
    };
    await sendEmail(mail, env);
    return json({ success: true }, 200, env);
  } catch (err) {
    return json({ success: true }, 200, env);
  }
}

async function bibliotecaPasswordReset(request: Request, env: Env): Promise<Response> {
  try {
    const data = await readBodyFlexible(request);
    const token = (data.token || '').toString().trim();
    const password = (data.password || data.senha || '').toString();
    if (!env.DB) return json({ success: false, error: 'Server error' }, 500, env);
    if (!token || !password) return json({ success: false, error: 'Dados inválidos' }, 400, env);

    const row = await env.DB
      .prepare('SELECT user_id, expires_at FROM password_resets WHERE token = ?1 LIMIT 1')
      .bind(token)
      .first<{ user_id: string; expires_at: string }>();
    if (!row) return json({ success: false, error: 'Token inválido' }, 400, env);
    if (new Date(row.expires_at).getTime() < Date.now()) {
      // Expired: cleanup and reject
      await env.DB.prepare('DELETE FROM password_resets WHERE token = ?1').bind(token).run();
      return json({ success: false, error: 'Token expirado' }, 400, env);
    }

    // Update password and verify email as a side effect
    const salt = base64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
    const hash = await hashPassword(password, salt);
    await env.DB.prepare('UPDATE users SET password_hash = ?1, salt = ?2, email_verified_at = COALESCE(email_verified_at, ?3) WHERE id = ?4')
      .bind(hash, salt, new Date().toISOString(), row.user_id)
      .run();
    // Consume all tokens for this email
    await env.DB.prepare('DELETE FROM password_resets WHERE user_id = ?1').bind(row.user_id).run();
    return json({ success: true }, 200, env);
  } catch (err) {
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function bibliotecaDownload(request: Request, env: Env): Promise<Response> {
  // Enforce authentication via the same JWT used by biblioteca pages
  const token = readJwtFromCookie(request);
  const payload = token ? await verifyJWT(token, env.JWT_SECRET || 'dev-secret') : null;
  if (!payload) {
    const to = new URL('/biblioteca/login', request.url);
    return Response.redirect(to.toString(), 302);
  }

  if (!env.BIBLIOTECA_R2) {
    console.error('[bibliotecaDownload] missing R2 binding BIBLIOTECA_R2');
    return json({ success: false, error: 'Internal server error' }, 500, env);
  }

  // Extract key from URL after '/biblioteca/download/'
  const url = new URL(request.url);
  const prefix = '/biblioteca/download/';
  let key = url.pathname.slice(prefix.length);
  // Basic safety: disallow traversals and empty keys
  if (!key || key.includes('..') || key.startsWith('/')) {
    console.info('[bibliotecaDownload] invalid input');
    return new Response('Arquivo não encontrado', { status: 404 });
  }

  const obj = await env.BIBLIOTECA_R2.get(key);
  if (!obj) {
    return new Response('Arquivo não encontrado', { status: 404 });
  }

  const headers = new Headers();
  const filename = key.split('/').pop() || 'download';

  const lower = filename.toLowerCase();
  const mime = lower.endsWith('.pdf') ? 'application/pdf'
    : lower.endsWith('.txt') ? 'text/plain; charset=utf-8'
    : lower.endsWith('.zip') ? 'application/zip'
    : lower.endsWith('.doc') ? 'application/msword'
    : lower.endsWith('.docx') ? 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
    : lower.endsWith('.xlsx') ? 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    : lower.endsWith('.pptx') ? 'application/vnd.openxmlformats-officedocument.presentationml.presentation'
    : lower.endsWith('.ppt') ? 'application/vnd.ms-powerpoint'
    : lower.endsWith('.jpg') || lower.endsWith('.jpeg') ? 'image/jpeg'
    : lower.endsWith('.png') ? 'image/png'
    : 'application/octet-stream';
  headers.set('content-type', mime);
  headers.set('content-disposition', `attachment; filename="${filename}"`);
  if (obj.httpEtag) headers.set('etag', obj.httpEtag);
  headers.set('cache-control', 'private, max-age=0');

  return new Response(obj.body, { status: 200, headers });
}

async function bibliotecaRegister(request: Request, env: Env): Promise<Response> {
  try {
    const data = await readBodyFlexible(request);
    const name = (data.name || data.nome || '').toString().trim().slice(0, 50);
    const last_name = (data.last_name || data.sobrenome || '').toString().trim().slice(0, 50);
    const email = (data.email || '').toString().trim().toLowerCase().slice(0, 100);
    const password = (data.password || data.senha || '').toString();
    // Additional fields from form
    const company = (data.company || data.empresa || '').toString().trim().slice(0, 100);
    const phoneRaw = (data.phone || data.telefone || '').toString();
    const phone = phoneRaw.replace(/[^0-9]/g, '').slice(0, 15);
    const cro = (data.cro || '').toString().trim().slice(0, 6);
    const cro_uf = (data.cro_uf || data.croUf || '').toString().trim().toUpperCase().slice(0, 2);
    const specialty = (data.specialty || data.especialidade || '').toString().trim().slice(0, 64);

    if (!env.DB) {
      return json({ success: false, error: 'Server not configured: missing D1 binding DB' }, 500, env);
    }
    if (!name || !last_name || !email || !password) {
      const errors: Record<string, string> = {};
      if (!name) errors.nome = 'Campo obrigatório';
      if (!last_name) errors.sobrenome = 'Campo obrigatório';
      if (!email) errors.email = 'Campo obrigatório';
      if (!password) errors.password = 'Campo obrigatório';
      return json({ success: false, error: 'Missing required fields', errors }, 400, env);
    }
    // Enforce CRO/CRO_UF pairing
    if ((cro && !cro_uf) || (!cro && cro_uf)) {
      const msg = 'Informe CRO e UF juntos.';
      return json({ success: false, error: msg, errors: { cro: msg } }, 400, env);
    }

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltB64 = base64urlEncode(salt);
    const passwordHash = await hashPassword(password, saltB64);

    const nowIso = new Date().toISOString();
    // Create table if needed is intentionally NOT done here; run migrations instead.
    try {
      const userId = generateUlid();
      // Insert user
      await env.DB
        .prepare('INSERT INTO users (id, email, password_hash, salt, created_at) VALUES (?1, ?2, ?3, ?4, ?5)')
        .bind(userId, email, passwordHash, saltB64, nowIso)
        .run();
      // Insert user profile
      await env.DB
        .prepare('INSERT INTO user_profiles (email, name, last_name, company, phone, cro, cro_uf, specialty) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)')
        .bind(email, name || null, last_name || null, company || null, phone || null, cro || null, cro_uf || null, specialty || null)
        .run();
    } catch (e: any) {
      if ((e && e.message || '').toLowerCase().includes('unique')) {
        return json({ success: false, error: 'Email já cadastrado', errors: { email: 'Email já cadastrado' } }, 409, env);
      }
      throw e;
    }

    // Generate a 6-digit verification code and store it with 30 days expiration
    const code = generateSixDigitCode();
    const created = new Date();
    const expires = new Date(created.getTime() + 30 * 24 * 60 * 60 * 1000);
    const verId = generateUlid();
    // Resolve user_id for this email (the one we just inserted)
    const userRow = await env.DB
      .prepare('SELECT id FROM users WHERE email = ?1 LIMIT 1')
      .bind(email)
      .first<{ id: string }>();
    const userIdForEmail = userRow ? userRow.id : '';
    await env.DB
      .prepare('INSERT INTO email_verifications (id, user_id, code, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)')
      .bind(verId, userIdForEmail, code, created.toISOString(), expires.toISOString())
      .run();

    // Send email with code
    const fromEmail = (env.FROM_EMAIL || '').toString().trim();
    if (fromEmail) {
      const label12 = 'FONT-SIZE:12PX;';
      const html = [
        `<b style='${label12}'>Olá, ${escapeHtml(name || email)}</b><br/>`,
        `Seu código de verificação é: <b>${code}</b><br/><br/>`,
        `Este código expira em 30 dias.`
      ].join('');
      const text = `Olá, ${name || email}\nSeu código de verificação é: ${code}\n\nO código expira em 30 dias.`;
      const mail: MailChannelsRequest = {
        personalizations: [{ to: [{ email }] }],
        from: { email: fromEmail, name: 'Dérig' },
        subject: '[Biblioteca] Verifique seu e-mail',
        content: [
          { type: 'text/plain', value: text },
          { type: 'text/html', value: html }
        ]
      };
      await sendEmail(mail, env);
    }

    // Do not log in yet; client should redirect to verification page
    return json({ success: true }, 200, env);
  } catch (err: any) {
    console.error('[bibliotecaRegister] error', err && (err.stack || err.message || err));
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function bibliotecaVerifyEmail(request: Request, env: Env): Promise<Response> {
  try {
    const data = await readBodyFlexible(request);
    const email = (data.email || '').toString().trim().toLowerCase().slice(0, 100);
    const code = (data.code || '').toString().trim();
    if (!env.DB) return json({ success: false, error: 'Server error' }, 500, env);
    if (!email || !code) return json({ success: false, error: 'Dados inválidos' }, 400, env);

    // Resolve user_id and profile name from email
    const userRow = await env.DB
      .prepare(`
        SELECT u.id as id, up.name as name, up.last_name as last_name
        FROM users u
        LEFT JOIN user_profiles up ON up.email = u.email
        WHERE u.email = ?1
        LIMIT 1`)
      .bind(email)
      .first<{ id: string; name: string | null; last_name: string | null }>();
    if (!userRow) return json({ success: false, error: 'Código inválido' }, 400, env);

    const row = await env.DB
      .prepare('SELECT code, expires_at FROM email_verifications WHERE user_id = ?1 ORDER BY created_at DESC LIMIT 1')
      .bind(userRow.id)
      .first<{ code: string; expires_at: string }>();
    if (!row) return json({ success: false, error: 'Código inválido' }, 400, env);
    if (new Date(row.expires_at).getTime() < Date.now()) return json({ success: false, error: 'Código expirado' }, 400, env);
    if (String(row.code) !== String(code)) return json({ success: false, error: 'Código inválido' }, 400, env);

    // Mark verified
    const nowIso = new Date().toISOString();
    await env.DB.prepare('UPDATE users SET email_verified_at = ?1 WHERE id = ?2').bind(nowIso, userRow.id).run();
    // Cleanup codes for this email
    await env.DB.prepare('DELETE FROM email_verifications WHERE user_id = ?1').bind(userRow.id).run();

    // Auto-login
    const fullName = [userRow?.name || '', userRow?.last_name || ''].filter(Boolean).join(' ').trim();
    const token = await signJWT({ sub: email, name: fullName }, env.JWT_SECRET || 'dev-secret', 24 * 60 * 60);
    const headers = new Headers();
    headers.append('set-cookie', buildAuthCookie(token, request));
    return new Response(JSON.stringify({ success: true }), { status: 200, headers: withJsonCors(headers, env) });
  } catch (err: any) {
    console.error('[bibliotecaVerifyEmail] error', err && (err.stack || err.message || err));
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function bibliotecaLogin(request: Request, env: Env): Promise<Response> {
  try {
    const data = await readBodyFlexible(request);
    const email = (data.email || '').toString().trim().toLowerCase();
    const password = (data.password || data.senha || '').toString();

    if (!env.DB) {
      return json({ success: false, error: 'Server not configured: missing D1 binding DB' }, 500, env);
    }
    if (!email || !password) {
      return json({ success: false, error: 'Missing required fields' }, 400, env);
    }

    const row = await env.DB
      .prepare(`
        SELECT u.email as email, up.name as name, up.last_name as last_name, u.password_hash as password_hash, u.salt as salt
        FROM users u
        LEFT JOIN user_profiles up ON up.email = u.email
        WHERE u.email = ?1
        LIMIT 1`)
      .bind(email)
      .first<{ email: string; name: string | null; last_name: string | null; password_hash: string; salt: string }>();

      if (!row) {
      return json({ success: false, error: 'Credenciais inválidas' }, 401, env);
    }

    const candidateHash = await hashPassword(password, row.salt);
    if (!timingSafeEqualStr(candidateHash, row.password_hash)) {
      return json({ success: false, error: 'Credenciais inválidas' }, 401, env);
    }

    // Block login if email is not verified
    const verifiedCheck = await env.DB
      .prepare('SELECT email_verified_at FROM users WHERE email = ?1 LIMIT 1')
      .bind(email)
      .first<{ email_verified_at: string | null }>();
    if (!verifiedCheck || !verifiedCheck.email_verified_at) {
      return json({ success: false, error: 'Credenciais inválidas' }, 401, env);
    }

    const fullName = [row.name || '', row.last_name || ''].filter(Boolean).join(' ').trim();
  const token = await signJWT({ sub: email, name: fullName }, env.JWT_SECRET || 'dev-secret', 24 * 60 * 60);
    const headers = new Headers();
    headers.append('set-cookie', buildAuthCookie(token, request));
    return new Response(JSON.stringify({ success: true }), { status: 200, headers: withJsonCors(headers, env) });
  } catch (err: any) {
    console.error('[bibliotecaLogin] error', err && (err.stack || err.message || err));
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function bibliotecaLogout(request: Request, env: Env): Promise<Response> {
  const headers = new Headers();
  headers.append('set-cookie', clearAuthCookie(request));
  return new Response(JSON.stringify({ success: true }), { status: 200, headers: withJsonCors(headers, env) });
}

function base64urlEncode(data: Uint8Array | string | unknown): string {
  let str: string;
  if (data instanceof Uint8Array) {
    str = btoa(String.fromCharCode(...data));
  } else if (typeof data === 'string') {
    str = btoa(data);
  } else {
    str = btoa(String(data));
  }
  return str.replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function base64urlDecodeToUint8Array(b64url: string): Uint8Array {
  const pad = b64url.length % 4 === 0 ? '' : '='.repeat(4 - (b64url.length % 4));
  const b64 = b64url.replaceAll('-', '+').replaceAll('_', '/') + pad;
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function importHmacKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyData = enc.encode(secret);
  return crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signJWT(payload: Record<string, unknown>, secret: string, expiresInSec?: number): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + (expiresInSec || 86400) };
  const enc = new TextEncoder();
  const headerB64 = base64urlEncode(JSON.stringify(header));
  const payloadB64 = base64urlEncode(JSON.stringify(body));
  const toSign = `${headerB64}.${payloadB64}`;
  const key = await importHmacKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(toSign));
  const sigB64 = base64urlEncode(new Uint8Array(sig));
  return `${toSign}.${sigB64}`;
}

async function verifyJWT(token: string, secret: string): Promise<Record<string, any> | null> {
  try {
    const [h, p, s] = token.split('.');
    if (!h || !p || !s) return null;
    const enc = new TextEncoder();
    const key = await importHmacKey(secret);
    const valid = await crypto.subtle.verify('HMAC', key, base64urlDecodeToUint8Array(s), enc.encode(`${h}.${p}`));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(base64urlDecodeToUint8Array(p)));
    if (typeof payload.exp === 'number' && Math.floor(Date.now() / 1000) > payload.exp) return null;
    return payload;
  } catch (_) {
    return null;
  }
}

function readJwtFromCookie(request: Request): string | null {
  const cookie = request.headers.get('cookie') || '';
  const parts = cookie.split(/;\s*/);
  for (const part of parts) {
    const [k, ...rest] = part.split('=');
    if (k === 'biblioteca_auth') return rest.join('=');
  }
  return null;
}

function buildAuthCookie(token: string, request: Request): string {
  const url = new URL(request.url);
  const isSecure = url.protocol === 'https:';
  const attrs = [
    `biblioteca_auth=${token}`,
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    isSecure ? 'Secure' : ''
  ].filter(Boolean);
  return attrs.join('; ');
}

function clearAuthCookie(request: Request): string {
  const url = new URL(request.url);
  const isSecure = url.protocol === 'https:';
  const attrs = [
    'biblioteca_auth=; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'HttpOnly',
    'Path=/',
    'SameSite=Lax',
    isSecure ? 'Secure' : ''
  ].filter(Boolean);
  return attrs.join('; ');
}

async function hashPassword(password: string, saltB64: string): Promise<string> {
  const enc = new TextEncoder();
  const data = enc.encode(`${saltB64}:${password}`);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64urlEncode(new Uint8Array(digest));
}

function timingSafeEqualStr(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}

async function readBodyFlexible(request: Request): Promise<Record<string, unknown>> {
  const ct = (request.headers.get('content-type') || '').toLowerCase();
  if (ct.includes('application/json')) {
    return await request.json();
  }
  if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
    const form = await request.formData();
    const obj: Record<string, unknown> = {};
    form.forEach((v, k) => {
      obj[k] = typeof v === 'string' ? v : ((v as File)?.name || '');
    });
    return obj;
  }
  try {
    return await request.json();
  } catch (_) {
    return {};
  }
}

function withJsonCors(headers: Headers, env: Env): Headers {
  headers.set('content-type', 'application/json');
  const allowOrigin = env.ALLOW_ORIGIN || '*';
  headers.set('access-control-allow-origin', allowOrigin);
  headers.set('access-control-allow-methods', 'POST, OPTIONS');
  headers.set('access-control-allow-headers', 'content-type');
  return headers;
}

// -----------------------------
// Centralized configuration (KV)
// -----------------------------
type KvBackedConfig = Partial<
  Pick<
    Env,
    | 'ALLOW_ORIGIN'
    | 'DKIM_DOMAIN'
    | 'DKIM_SELECTOR'
    | 'EMAIL_CONTACT'
    | 'EMAIL_REGISTRATION'
    | 'EMAIL_WORKWITHUS'
    | 'FROM_EMAIL'
  >
> & Record<string, unknown>;

const KV_CONFIG_KEY = 'config'; // Key inside CONFIG KV that stores JSON blob
let CONFIG_CACHE: { at: number; data: KvBackedConfig } | null = null;
const CONFIG_TTL_MS = 5 * 60 * 1000; // 5 minutes

async function hydrateEnvFromKV(env: Env): Promise<void> {
  try {
    if (!env.CONFIG) return;
    let obj: KvBackedConfig | null = null;
    const now = Date.now();
    if (CONFIG_CACHE && now - CONFIG_CACHE.at < CONFIG_TTL_MS) {
      obj = CONFIG_CACHE.data;
    } else {
      const raw = await env.CONFIG.get(KV_CONFIG_KEY, 'text');
      if (!raw) return;
      try {
        obj = JSON.parse(raw);
      } catch (_) {
        console.warn('[config] invalid JSON stored in KV under key', KV_CONFIG_KEY);
        return;
      }
      if (!obj || typeof obj !== 'object') return;
      CONFIG_CACHE = { at: now, data: obj };
    }

    // Only allow-list non-secret keys to flow from KV to env.
    // Secrets must remain configured via Cloudflare secrets: MC_API_KEY, DKIM_PRIVATE_KEY.
    const allowedKeys: Array<keyof KvBackedConfig> = [
      'ALLOW_ORIGIN',
      'DKIM_DOMAIN',
      'DKIM_SELECTOR',
      'EMAIL_CONTACT',
      'EMAIL_REGISTRATION',
      'EMAIL_WORKWITHUS',
      'FROM_EMAIL',
    ];

    for (const k of allowedKeys) {
      const v = (obj as any)[k];
      if (v === undefined || v === null) continue;
      // Do not overwrite if already provided by environment/vars/secrets.
      if ((env as any)[k] === undefined || (env as any)[k] === null || (env as any)[k] === '') {
        (env as any)[k] = String(v);
      }
    }
  } catch (e: any) {
    console.warn('[config] hydrateEnvFromKV error', e && (e.stack || e.message || e));
  }
}

async function sendContactEmail(request: Request, env: Env): Promise<Response> {
  try {
    const formData = await request.formData();
    const name = (formData.get('nome') || '').toString().trim();
    const email = (formData.get('email') || '').toString().trim();
    const ajuda = (formData.get('ajuda') || '').toString().trim();
    const mensagemForm = (formData.get('mensagem') || '').toString().trim();
    const opt1 = formData.get('opt1');
    const opt2 = formData.get('opt2');

    console.log('[contato] parsed form', {
      name,
      email,
      ajuda_len: ajuda.length,
      mensagem_len: mensagemForm.length,
      has_opt1: Boolean(opt1),
      has_opt2: Boolean(opt2)
    });

    if (!name || !email) {
      console.warn('[contato] missing required fields', { hasName: Boolean(name), hasEmail: Boolean(email) });
      return json({ success: false, error: 'Missing required fields.' }, 400, env);
    }

    const toEmail = (env.EMAIL_CONTACT || '').toString().trim();
    const fromEmail = (env.FROM_EMAIL || '').toString().trim();
    console.log('[contato] config', {
      toEmail,
      hasFromEmail: Boolean(fromEmail),
      hasApiKey: Boolean(env.MC_API_KEY),
      hasDkim: Boolean(env.DKIM_PRIVATE_KEY)
    });
    if (!toEmail || !fromEmail) {
      return json({ success: false, error: 'Server not configured: missing TO EMAIL or FROM EMAIL' }, 500, env);
    }

    const labelStyle = 'FONT-SIZE:12PX;';
    const esc = (s: string) => escapeHtml(s || '');
    const msgHtmlLines = [
      `<b style='${labelStyle}'>Nome:  </b>${esc(name)}<br />`,
      `<b style='${labelStyle}'>E-mail:  </b>${esc(email)}<br />`,
      `<b style='${labelStyle}'>Como podemos te ajudar?:  </b>${esc(ajuda)}<br />`,
      `<b style='${labelStyle}'>Mensagem:  </b>${esc(mensagemForm)}<br />`,
    ];

    if (opt1) msgHtmlLines.push(`${esc(String(opt1))}<br />`);
    if (opt2) msgHtmlLines.push(`${esc(String(opt2))}<br />`);

    const messageHtml = msgHtmlLines.join('');
    const messageText = [
      `Nome: ${name}`,
      `E-mail: ${email}`,
      `Como podemos te ajudar?: ${ajuda}`,
      `Mensagem: ${mensagemForm}`,
      opt1 ? String(opt1) : '',
      opt2 ? String(opt2) : '',
      '', ''
    ].filter(Boolean).join('\n');

    const useApiKey = Boolean(env.MC_API_KEY);

    const mailObject: MailChannelsRequest = {
      personalizations: [
        {
          to: [{ email: toEmail, name: 'Dérig' }],
          ...(useApiKey ? {} : {
            dkim_domain: env.DKIM_DOMAIN || undefined,
            dkim_selector: env.DKIM_SELECTOR || undefined,
            dkim_private_key: env.DKIM_PRIVATE_KEY || undefined,
          })
        }
      ],
      from: { email: fromEmail, name: name },
      reply_to: { email, name },
      subject: '[Contato] Nova mensagem',
      content: [
        { type: 'text/plain', value: messageText },
        { type: 'text/html', value: messageHtml }
      ]
    };

    const res = await sendEmail(mailObject, env);
    console.log('[contato] sendEmail result', { status: res.status });
    return res;
  } catch (err: any) {
    console.error('[contato] handler error', err && (err.stack || err.message || err));
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function sendRegistrationEmail(request: Request, env: Env): Promise<Response> {
  try {
    const formData = await request.formData();
    // Personal info
    const nome = (formData.get('nome') || '').toString().trim();
    const email = (formData.get('email') || '').toString().trim();
    const cpf = (formData.get('cpf') || '').toString().trim();
    const rg = (formData.get('rg') || '').toString().trim();
    const dataNascimento = (formData.get('dataNascimento') || formData.get('data_nascimento') || '').toString().trim();
    const foneFixo = (formData.get('foneFixo') || formData.get('telefone') || '').toString().trim();
    const celular = (formData.get('celular') || '').toString().trim();
    // Professional
    const cro = (formData.get('cro') || '').toString().trim();
    const croUf = (formData.get('croUf') || formData.get('cro_uf') || '').toString().trim();
    const especialidade = (formData.get('especialidade') || '').toString().trim();
    // Address
    const cep = (formData.get('cep') || '').toString().trim();
    const rua = (formData.get('rua') || formData.get('logradouro') || '').toString().trim();
    const numero = (formData.get('numero') || '').toString().trim();
    const complemento = (formData.get('complemento') || '').toString().trim();
    const bairro = (formData.get('bairro') || '').toString().trim();
    const cidade = (formData.get('cidade') || '').toString().trim();
    const uf = (formData.get('uf') || '').toString().trim();

    console.log('[cadastro] parsed form (subset)', {
      nome,
      email,
      cpf_len: cpf.length,
      cro,
      cidade,
      uf
    });

    if (!nome || !email) {
      console.warn('[cadastro] missing required fields', { hasNome: Boolean(nome), hasEmail: Boolean(email) });
      return json({ success: false, error: 'Missing required fields.' }, 400, env);
    }

    const toEmail = (env.EMAIL_REGISTRATION || '').toString().trim();
    const fromEmail = (env.FROM_EMAIL || '').toString().trim();
    console.log('[cadastro] config', {
      toEmail,
      hasFromEmail: Boolean(fromEmail),
      hasApiKey: Boolean(env.MC_API_KEY),
      hasDkim: Boolean(env.DKIM_PRIVATE_KEY)
    });
    if (!toEmail || !fromEmail) {
      return json({ success: false, error: 'Server not configured: missing TO EMAIL or FROM EMAIL' }, 500, env);
    }

    const label12 = 'FONT-SIZE:12PX;';
    const label20 = 'FONT-SIZE:20PX;';
    const esc = (s: string) => escapeHtml(s || '');
    const linesHtml = [
      `<b style='${label20}'>Informações pessoais  </b><br />`,
      `<b style='${label12}'>Nome:  </b>${esc(nome)}<br />`,
      `<b style='${label12}'>E-mail:  </b>${esc(email)}<br />`,
      `<b style='${label12}'>CPF:  </b>${esc(cpf)}<br />`,
      `<b style='${label12}'>RG:  </b>${esc(rg)}<br />`,
      `<b style='${label12}'>Data de nascimento:  </b>${esc(dataNascimento)}<br />`,
      `<b style='${label12}'>Telefone fixo:  </b>${esc(foneFixo)}<br />`,
      `<b style='${label12}'>Celular:  </b>${esc(celular)}<br /><br />`,

      `<b style='${label20}'>Informações profissionais  </b><br />`,
      `<b style='${label12}'>CRO:  </b>${esc(cro)} - UF: ${esc(croUf)}<br />`,
      `<b style='${label12}'>Especialidade:  </b>${esc(especialidade)}<br /><br />`,

      `<b style='${label20}'>Endereço  </b><br />`,
      `<b style='${label12}'>CEP:  </b>${esc(cep)}<br />`,
      `<b style='${label12}'>Logradouro:  </b>${esc(rua)} - Número: ${esc(numero)}<br />`,
      `<b style='${label12}'>Complemento:  </b>${esc(complemento)}<br />`,
      `<b style='${label12}'>Bairro:  </b>${esc(bairro)}<br />`,
      `<b style='${label12}'>Cidade:  </b>${esc(cidade)} - UF: ${esc(uf)}<br /><br />`,
    ];
    const messageHtml = linesHtml.join('');
    const messageText = [
      'Informações pessoais',
      `Nome: ${nome}`,
      `E-mail: ${email}`,
      `CPF: ${cpf}`,
      `RG: ${rg}`,
      `Data de nascimento: ${dataNascimento}`,
      `Telefone fixo: ${foneFixo}`,
      `Celular: ${celular}`,
      '',
      'Informações profissionais',
      `CRO: ${cro} - UF: ${croUf}`,
      `Especialidade: ${especialidade}`,
      '',
      'Endereço',
      `CEP: ${cep}`,
      `Logradouro: ${rua} - Número: ${numero}`,
      `Complemento: ${complemento}`,
      `Bairro: ${bairro}`,
      `Cidade: ${cidade} - UF: ${uf}`,
    ].join('\n');

    const useApiKey = Boolean(env.MC_API_KEY);

    const mailObject: MailChannelsRequest = {
      personalizations: [
        {
          to: [{ email: toEmail, name: 'Dérig' }],
          ...(useApiKey ? {} : {
            dkim_domain: env.DKIM_DOMAIN || undefined,
            dkim_selector: env.DKIM_SELECTOR || undefined,
            dkim_private_key: env.DKIM_PRIVATE_KEY || undefined,
          })
        }
      ],
      from: { email: fromEmail, name: nome },
      reply_to: { email, name: nome },
      subject: '[Cadastro] Novo cadastro',
      content: [
        { type: 'text/plain', value: messageText },
        { type: 'text/html', value: messageHtml }
      ]
    };

    return await sendEmail(mailObject, env);
  } catch (_err) {
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function sendWorkWithUsEmail(request: Request, env: Env): Promise<Response> {
  try {
    const formData = await request.formData();
    const name = (formData.get('nome') || '').toString().trim();
    const email = (formData.get('email') || '').toString().trim();
    const celular = (formData.get('celular') || formData.get('telefone') || '').toString().trim();

    console.log('[trabalhe] parsed form', {
      name,
      email,
      hasCelular: Boolean(celular)
    });

    if (!name || !email || !celular) {
      console.warn('[trabalhe] missing required fields', { hasName: Boolean(name), hasEmail: Boolean(email), hasCelular: Boolean(celular) });
      return json({ success: false, error: 'Missing required fields.' }, 400, env);
    }

    const toEmail = (env.EMAIL_WORKWITHUS || '').toString().trim();
    const fromEmail = (env.FROM_EMAIL || '').toString().trim();
    console.log('[trabalhe] config', {
      toEmail,
      hasFromEmail: Boolean(fromEmail),
      hasApiKey: Boolean(env.MC_API_KEY),
      hasDkim: Boolean(env.DKIM_PRIVATE_KEY)
    });
    if (!toEmail || !fromEmail) {
      return json({ success: false, error: 'Server not configured: missing TO EMAIL or FROM EMAIL' }, 500, env);
    }

    const labelStyle = 'FONT-SIZE:12PX;';
    const esc = (s: string) => escapeHtml(s || '');
    const msgHtmlLines = [
      `<b style='${labelStyle}'>Nome:  </b>${esc(name)}<br />`,
      `<b style='${labelStyle}'>E-mail:  </b>${esc(email)}<br />`,
      `<b style='${labelStyle}'>Telefone:  </b>${esc(celular)}<br /><br /><br /><br /><br />`,
    ];
    const messageHtml = msgHtmlLines.join('');
    const messageText = [
      `Nome: ${name}`,
      `E-mail: ${email}`,
      `Telefone: ${celular}`,
      '', '', '', '', ''
    ].join('\n');

    // Only handle a single file (first one) if multiple were sent
    const firstFile = (formData.get && (formData.get('file') as unknown as File | null))
      || ((formData.getAll && (formData.getAll('file') as unknown as File[]) || [])[0] || null);

    const attachments: MailChannelsAttachment[] = [];
    // Enforce max size 10MB
    const MAX_BYTES = 10 * 1024 * 1024;
    if (firstFile && firstFile.size > MAX_BYTES) {
      console.warn('[trabalhe] file too large', { size: firstFile.size, MAX_BYTES });
      return json({ success: false, error: 'Arquivo muito grande. Tamanho máximo: 10MB.' }, 400, env);
    }
    if (firstFile && typeof firstFile.arrayBuffer === 'function' && firstFile.size > 0) {
      const buf = await firstFile.arrayBuffer();
      const b64 = arrayBufferToBase64(buf);
      attachments.push({
        content: b64,
        filename: firstFile.name || 'arquivo',
        type: firstFile.type || 'application/octet-stream'
      });

      console.log('[trabalhe] attachment prepared', {
        filename: firstFile.name || 'arquivo',
        type: firstFile.type || 'application/octet-stream',
        size: firstFile.size
      });
    }

    const useApiKey = Boolean(env.MC_API_KEY);

    const mailObject: MailChannelsRequest = {
      personalizations: [
        {
          to: [{ email: toEmail, name: 'Dérig' }],
          ...(useApiKey ? {} : {
            dkim_domain: env.DKIM_DOMAIN || undefined,
            dkim_selector: env.DKIM_SELECTOR || undefined,
            dkim_private_key: env.DKIM_PRIVATE_KEY || undefined,
          })
        }
      ],
      from: { email: fromEmail, name: name },
      reply_to: { email, name },
      subject: '[Trabalhe Conosco] Nova mensagem',
      content: [
        { type: 'text/plain', value: messageText },
        { type: 'text/html', value: messageHtml }
      ]
    };

    if (attachments.length) {
      mailObject.attachments = attachments;
    }

    return await sendEmail(mailObject, env);
  } catch (_err) {
    return json({ success: false, error: 'Server error' }, 500, env);
  }
}

async function sendNewsletterEmail(_request: Request, env: Env): Promise<Response> {
  return json({ success: false, error: 'Server error' }, 500, env);
}

async function sendEmail(mail: MailChannelsRequest, env: Env): Promise<Response> {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (env.MC_API_KEY) {
    headers['X-Api-Key'] = env.MC_API_KEY;
  }
  const mcRes = await fetch('https://api.mailchannels.net/tx/v1/send', {
    method: 'POST',
    headers,
    body: JSON.stringify(mail)
  });

  if (!mcRes.ok) {
    const text = await mcRes.text();
    console.error('MailChannels send failed', { status: mcRes.status, body: text });
    return json({ success: false, error: 'Email send failed', status: mcRes.status, details: text }, 502, env);
  }

  console.log('[sendEmail] MailChannels accepted message', {
    to: (mail.personalizations && mail.personalizations[0] && mail.personalizations[0].to) || [],
    from: mail.from,
    usedApiKey: Boolean(env.MC_API_KEY)
  });
  return json({ success: true }, 200, env);
}

function json(obj: unknown, status: number = 200, env: Env): Response {
  const headers = new Headers({ 'content-type': 'application/json' });
  const allowOrigin = env.ALLOW_ORIGIN || '*';
  headers.set('access-control-allow-origin', allowOrigin);
  headers.set('access-control-allow-methods', 'POST, OPTIONS');
  headers.set('access-control-allow-headers', 'content-type');
  return new Response(JSON.stringify(obj), { status, headers });
}

function corsPreflight(env: Env): Response {
  const headers = new Headers();
  const allowOrigin = env.ALLOW_ORIGIN || '*';
  headers.set('access-control-allow-origin', allowOrigin);
  headers.set('access-control-allow-methods', 'POST, OPTIONS');
  headers.set('access-control-allow-headers', 'content-type');
  headers.set('access-control-max-age', '86400');
  return new Response(null, { status: 204, headers });
}

function escapeHtml(str: string): string {
  return str
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000; // avoid call stack limits
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode.apply(null, Array.from(chunk) as unknown as number[]);
  }
  return btoa(binary);
}

function generateSixDigitCode(): string {
  const n = crypto.getRandomValues(new Uint32Array(1))[0] % 1000000;
  return n.toString().padStart(6, '0');
}

// ULID generator (Crockford's Base32)
// Time component in ms and 80 bits of randomness for uniqueness
function generateUlid(date?: Date): string {
  const time = (date ? date.getTime() : Date.now());
  const timePart = encodeTime(time);
  const randPart = encodeRandom(16); // 16 bytes => 80 bits -> 16 chars base32
  return timePart + randPart;
}

const CROCK = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

function encodeTime(time: number): string {
  // 48-bit time -> 10 characters base32
  let t = BigInt(time);
  const mask = BigInt(31);
  const out: string[] = new Array(10);
  for (let i = 9; i >= 0; i--) {
    const idx = Number(t & mask);
    out[i] = CROCK[idx];
    t >>= BigInt(5);
  }
  return out.join('');
}

function encodeRandom(bytesLen: number): string {
  const bytes = new Uint8Array(bytesLen);
  crypto.getRandomValues(bytes);
  // Each 5 bits -> one char
  let bits = 0;
  let value = 0;
  let out = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      const idx = (value >>> (bits - 5)) & 31;
      out += CROCK[idx];
      bits -= 5;
    }
  }
  if (bits > 0) {
    const idx = (value << (5 - bits)) & 31;
    out += CROCK[idx];
  }
  // Ensure length 16
  return out.slice(0, 16).padEnd(16, '0');
}

// Minimal MailChannels request typings used by this worker
interface MailChannelsAttachment {
  content: string; // base64
  filename: string;
  type: string;
}

interface MailChannelsRequest {
  personalizations: Array<{
    to: Array<{ email: string; name?: string }>;
    dkim_domain?: string;
    dkim_selector?: string;
    dkim_private_key?: string;
  }>;
  from: { email: string; name?: string };
  reply_to?: { email: string; name?: string };
  subject: string;
  content: Array<{ type: 'text/plain' | 'text/html'; value: string }>;
  attachments?: MailChannelsAttachment[];
}
