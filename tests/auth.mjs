import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import worker from '../dist/server/index.js';

const sqlite = new DatabaseSync(':memory:');
sqlite.exec(readFileSync(new URL('../drizzle/0000_fuzzy_famine.sql', import.meta.url),'utf8'));
sqlite.prepare('INSERT INTO board (id,revision,data) VALUES (1,1,?)').run(JSON.stringify({existing:true}));
sqlite.exec(readFileSync(new URL('../drizzle/0001_thankful_valkyrie.sql', import.meta.url),'utf8'));
const env = {OWNER_EMAIL:'owner@example.com',DB:{
  prepare(sql) {
    let args = [];
    return {bind(...values){args=values;return this;},async first(){return sqlite.prepare(sql).get(...args) || null;},async run(){const r=sqlite.prepare(sql).run(...args);return {meta:{changes:r.changes}};}};
  },
  async batch(items){sqlite.exec('BEGIN');try {const out=[];for(const item of items)out.push(await item.run());sqlite.exec('COMMIT');return out;}catch(error){sqlite.exec('ROLLBACK');throw error;}}
}};
const base='https://ava.test';
const owner={'oai-authenticated-user-id':'test-owner','oai-authenticated-user-email':'owner@example.com'};
const call=(path,{method='GET',body,headers={}}={})=>worker.fetch(new Request(base+path,{method,headers:{...(method==='POST'||method==='PUT'?{'Origin':base,'Content-Type':'application/json'}:{}),...headers},...(body===undefined?{}:{body:JSON.stringify(body)})}),env);
const cookie=response=>response.headers.get('Set-Cookie').split(';')[0];
const credentials={username:'salon-test',password:crypto.randomUUID()+'-Password'};
assert.equal((await call('/')).status,302);
assert.equal((await call('/login')).status,200);
assert.equal((await call('/api/board')).status,401);
assert.equal((await call('/api/board',{headers:owner})).status,401,'ChatGPT identity cannot bypass salon password');
assert.equal((await call('/api/auth/setup',{method:'POST',body:credentials})).status,403);
assert.equal((await call('/api/auth/setup',{method:'POST',body:credentials,headers:{...owner,Origin:'https://evil.test'}})).status,403);
assert.equal((await call('/setup',{headers:{...owner,'oai-authenticated-user-email':'other@example.com'}})).status,403);
assert.equal((await call('/api/auth/setup',{method:'POST',body:credentials,headers:owner})).status,200);
assert.equal(sqlite.prepare('SELECT data FROM board').get().data,'{"existing":true}','Setup preserves existing turns');
assert.notEqual(sqlite.prepare('SELECT password_hash FROM salon_account').get().password_hash,credentials.password);
const login=(remember=false)=>call('/api/auth/login',{method:'POST',body:{...credentials,remember}});
assert.equal((await call('/api/auth/login',{method:'POST',body:{...credentials,password:'wrong'}})).status,401);
const a=await login(),b=await login(true);assert.equal(a.status,200);assert.equal(b.status,200);
assert.doesNotMatch(a.headers.get('Set-Cookie'),/Max-Age/);
assert.match(b.headers.get('Set-Cookie'),/Max-Age=2592000/);
const expiries=sqlite.prepare('SELECT expires_at FROM salon_sessions ORDER BY expires_at').all();
assert.ok(expiries[1].expires_at-expiries[0].expires_at >= 29*86400000);
const ah={Cookie:cookie(a)},bh={Cookie:cookie(b)};assert.notEqual(ah.Cookie,bh.Cookie,'Each device gets its own session');
assert.match(a.headers.get('Set-Cookie'),/HttpOnly; Secure; SameSite=Lax/);
assert.equal((await call('/',{headers:ah})).status,200);
assert.equal((await call('/login',{headers:bh})).status,302,'Remembered login skips login page');
assert.equal((await (await call('/api/account',{headers:ah})).json()).email,credentials.username);
const days=['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
const data={services:['Dip'],staffByDay:Object.fromEntries(days.map(d=>[d,[{id:'tech1',name:'Tyson'}]])),orderByDay:Object.fromEntries(days.map(d=>[d,['tech1']])),entries:{'Monday|tech1|1':'Dip'}};
assert.equal((await call('/api/board',{method:'PUT',body:{revision:1,data},headers:ah})).status,200);
assert.deepEqual((await (await call('/api/board',{headers:bh})).json()).data,data,'Laptop reads phone edits');
assert.equal((await call('/api/board',{method:'PUT',body:{revision:1,data},headers:bh})).status,409,'Stale writes cannot overwrite');
assert.equal((await call('/api/board',{method:'PUT',body:{revision:2,data},headers:{...ah,Origin:'https://evil.test'}})).status,403);
assert.equal((await call('/api/auth/logout',{method:'POST',headers:ah})).status,200);
assert.equal((await call('/api/board',{headers:ah})).status,401);
assert.equal((await call('/api/board',{headers:bh})).status,200,'Logout only ends this device session');
assert.equal((await call('/api/auth/setup',{method:'POST',headers:owner,body:{...credentials,password:credentials.password+'new'}})).status,200);
assert.equal((await call('/api/board',{headers:bh})).status,401,'Password change revokes all old sessions');
assert.equal((await login()).status,401,'Old password no longer works');
assert.deepEqual(JSON.parse(sqlite.prepare('SELECT data FROM board').get().data),data);
sqlite.prepare('UPDATE login_attempts SET attempts = 10').run();
assert.equal((await login()).status,429,'Login attempts are rate limited');
console.log('Passed: setup ownership, password hashing/login, two device shared data, conflict protection, CSRF, logout, password change, migration preservation and rate limit.');
