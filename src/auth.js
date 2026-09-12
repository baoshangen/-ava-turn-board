import { scryptAsync } from '@noble/hashes/scrypt';

const COOKIE = '__Host-ava-session';
const LIFETIME = 24 * 60 * 60;
const REMEMBER_LIFETIME = 30 * 24 * 60 * 60;
const encoder = new TextEncoder();
const hex = bytes => Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
const unhex = value => Uint8Array.from(value.match(/../g), x => parseInt(x, 16));
const random = size => hex(crypto.getRandomValues(new Uint8Array(size)));
const digest = async value => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))));
const owner = (request, env) => Boolean(request.headers.get('oai-authenticated-user-id')) && request.headers.get('oai-authenticated-user-email')?.toLowerCase() === env.OWNER_EMAIL?.toLowerCase();
const jsonAuth = (data, status = 200, extra = {}) => Response.json(data, {status, headers: {'Cache-Control':'no-store', ...extra}});
const cookie = (token, age = null) => `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax${age === null ? '' : '; Max-Age=' + age}`;
const readToken = request => {
  const value = (request.headers.get('Cookie') || '').split(';').map(x => x.trim()).find(x => x.startsWith(COOKIE + '='))?.slice(COOKIE.length + 1);
  return value && /^[a-f0-9]{64}$/.test(value) ? value : null;
};
let activeHashes = 0;
const hashPassword = async (password, salt) => {
  if (activeHashes >= 3) throw new Error('Busy');
  activeHashes++;
  try { return await scryptAsync(password, unhex(salt), {N:16384, r:8, p:5, dkLen:32, maxmem:32 * 1024 * 1024}); }
  finally { activeHashes--; }
};
const constantEqual = (a,b) => {
  if (a.length !== b.length) return false;
  let diff = 0; for (let i=0;i<a.length;i++) diff |= a[i] ^ b[i]; return diff === 0;
};
const parseInput = async request => {
  if (!request.headers.get('Content-Type')?.startsWith('application/json')) throw new Error('input');
  const reader = request.body?.getReader();
  if (!reader) throw new Error('input');
  let body = '', size = 0;
  const decoder = new TextDecoder();
  while (true) {
    const {done,value} = await reader.read(); if (done) break;
    size += value.byteLength; if (size > 4096) { await reader.cancel(); throw new Error('input'); }
    body += decoder.decode(value, {stream:true});
  }
  body += decoder.decode();
  const data = JSON.parse(body);
  if (!data || typeof data.username !== 'string' || typeof data.password !== 'string' || data.username.length > 40 || data.password.length > 128) throw new Error('input');
  return {username:data.username.trim().toLowerCase(), password:data.password, remember:data.remember === true};
};
async function throttle(request, env) {
  const now = Date.now(), windowEnd = (Math.floor(now / 900000) + 1) * 900000;
  const key = await digest((request.headers.get('CF-Connecting-IP') || 'shared') + ':' + windowEnd);
  const row = await env.DB.prepare('INSERT INTO login_attempts (key, attempts, expires_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET attempts = attempts + 1 RETURNING attempts').bind(key, windowEnd).first();
  await env.DB.prepare('DELETE FROM login_attempts WHERE expires_at < ?').bind(now).run();
  return row.attempts <= 10;
}
export async function getSession(request, env) {
  const token = readToken(request);
  if (!token) return null;
  return env.DB.prepare('SELECT a.username FROM salon_sessions s JOIN salon_account a ON a.id = 1 AND a.epoch = s.epoch WHERE s.token_hash = ? AND s.expires_at > ?').bind(await digest(token), Date.now()).first();
}
export async function authRoute(request, env, assets) {
  const url = new URL(request.url), path = url.pathname;
  if (['/login', '/login.html', '/auth-ui.js'].includes(path)) {
    if (request.method !== 'GET') return jsonAuth({error:'Method not allowed'},405);
    if (path !== '/auth-ui.js' && await getSession(request,env)) return Response.redirect(url.origin + '/',302);
    const asset = assets[path === '/auth-ui.js' ? path : '/login.html'];
    return new Response(asset.body, {headers:{'Content-Type':asset.type,'Cache-Control':'no-store'}});
  }
  if (path === '/setup') {
    if (request.method !== 'GET') return jsonAuth({error:'Method not allowed'},405);
    if (!owner(request, env)) {
      if (!request.headers.get('oai-authenticated-user-id')) return Response.redirect(url.origin + '/signin-with-chatgpt?return_to=%2Fsetup',302);
      return new Response('Chỉ chủ tiệm có quyền thiết lập tài khoản.',{status:403,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});
    }
    return new Response(assets['/login.html'].body,{headers:{'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'}});
  }
  if (!path.startsWith('/api/auth/')) return null;
  if (path === '/api/auth/status' && request.method === 'GET') {
    const account = await env.DB.prepare('SELECT username FROM salon_account WHERE id = 1').first();
    return jsonAuth({configured:!!account, canSetup:owner(request, env), username:owner(request, env) ? account?.username : undefined});
  }
  if (request.method !== 'POST') return jsonAuth({error:'Method not allowed'},405);
  if (request.headers.get('Origin') !== url.origin || request.headers.get('Sec-Fetch-Site') === 'cross-site') return jsonAuth({error:'Yêu cầu không hợp lệ.'},403);
  if (path === '/api/auth/logout') {
    const token = readToken(request);
    if (token) await env.DB.prepare('DELETE FROM salon_sessions WHERE token_hash = ?').bind(await digest(token)).run();
    return jsonAuth({ok:true},200,{'Set-Cookie':cookie('',0)});
  }
  if (path === '/api/auth/setup') {
    if (!owner(request, env)) return jsonAuth({error:'Chỉ chủ tiệm có quyền thiết lập tài khoản.'},403);
    let input; try { input = await parseInput(request); } catch { return jsonAuth({error:'Kiểm tra lại tên đăng nhập và mật khẩu.'},400); }
    const {username,password} = input;
    if (!/^[a-z0-9._-]{3,40}$/.test(username) || password.length < 15) return jsonAuth({error:'Tên đăng nhập: 3–40 ký tự (a–z, số, dấu . _ -). Mật khẩu: ít nhất 15 ký tự.'},400);
    const salt = random(32), epoch = random(16), passwordHash = hex(await hashPassword(password,salt));
    await env.DB.batch([
      env.DB.prepare('INSERT INTO salon_account (id, username, password_hash, salt, epoch) VALUES (1, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash, salt = excluded.salt, epoch = excluded.epoch').bind(username,passwordHash,salt,epoch),
      env.DB.prepare('DELETE FROM salon_sessions')
    ]);
    return jsonAuth({ok:true},200,{'Set-Cookie':cookie('',0)});
  }
  if (path === '/api/auth/login') {
    if (!(await throttle(request,env))) return jsonAuth({error:'Đã thử quá nhiều lần. Vui lòng chờ tối đa 15 phút rồi thử lại.'},429,{'Retry-After':'900'});
    let input; try { input = await parseInput(request); } catch { return jsonAuth({error:'Tên đăng nhập hoặc mật khẩu chưa đúng.'},400); }
    const account = await env.DB.prepare('SELECT username, password_hash, salt, epoch FROM salon_account WHERE id = 1').first();
    if (!account) return jsonAuth({error:'Chủ tiệm chưa thiết lập tài khoản. Vui lòng liên hệ chủ tiệm.'},503);
    const candidate = await hashPassword(input.password,account.salt);
    if (!constantEqual(candidate,unhex(account.password_hash)) || input.username !== account.username) return jsonAuth({error:'Tên đăng nhập hoặc mật khẩu chưa đúng.'},401);
    const token = random(32);
    const lifetime = input.remember ? REMEMBER_LIFETIME : LIFETIME;
    await env.DB.batch([
      env.DB.prepare('INSERT INTO salon_sessions (token_hash, epoch, expires_at) VALUES (?, ?, ?)').bind(await digest(token),account.epoch,Date.now()+lifetime*1000),
      env.DB.prepare('DELETE FROM salon_sessions WHERE expires_at <= ?').bind(Date.now())
    ]);
    return jsonAuth({ok:true},200,{'Set-Cookie':cookie(token,input.remember ? lifetime : null)});
  }
  return jsonAuth({error:'Not found'},404);
}
