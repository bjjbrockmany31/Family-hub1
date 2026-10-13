'use strict';
// Homebase standalone server: Node 20+; no npm packages or third-party auth services.
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'homebase.json');
const INDEX = fs.readFileSync(path.join(__dirname, 'index.html'));
const MAX_BODY = 8 * 1024 * 1024;
const CORS = {}; // served from the same origin; don't allow cross-origin API access
fs.mkdirSync(DATA_DIR, {recursive:true, mode:0o700});
let store;
try {store=JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))} catch(e) {store={users:[],families:[],sessions:[]};}
for(const k of ['users','families','sessions'])if(!Array.isArray(store[k]))store[k]=[];
const attemptWindow=new Map();
let writes=0;
function persist(){const temp=DATA_FILE+'.tmp';fs.writeFileSync(temp, JSON.stringify(store), {mode:0o600});fs.renameSync(temp,DATA_FILE);writes++;}
function rand(bytes=24){return crypto.randomBytes(bytes).toString('base64url')}
function sha(s){return crypto.createHash('sha256').update(s).digest('hex')}
function hashPassword(pass,salt){return crypto.scryptSync(pass,salt,64).toString('hex')}
function validPassword(pass){return typeof pass==='string'&&pass.length>=8&&pass.length<=128}
function passwordMatches(user,pass){const h=hashPassword(pass,user.salt);return crypto.timingSafeEqual(Buffer.from(h,'hex'),Buffer.from(user.hash,'hex'))}
function respond(res,code,data,headers={}){res.writeHead(code,{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff',...headers});res.end(JSON.stringify(data))}
function error(res,code,message){return respond(res,code,{error:message})}
function profile(u){return {id:u.id,username:u.username,displayName:u.displayName,avatar:u.avatar,joined:u.joined,triviaRight:u.triviaRight||0,triviaAttempts:u.triviaAttempts||0,solvedHunts:u.solvedHunts||0,activity:u.activity||[]}}
function lookupToken(req){const h=req.headers.authorization||'';if(!h.startsWith('Bearer '))return null;const hashed=sha(h.slice(7));const session=store.sessions.find(s=>s.hash===hashed&&s.expires>Date.now());if(!session)return null;const user=store.users.find(u=>u.id===session.userId);const family=user&&store.families.find(f=>f.id===user.familyId);return user&&family?{user,family,session}:null}
function familyPayload(user,family,token){return {account:profile(user),accounts:store.users.filter(u=>u.familyId===family.id).map(profile),db:family.db,version:family.version,familyId:family.id,inviteCode:family.inviteCode,...(token?{token}:{})}}
function createSession(user){const token=rand(40);store.sessions.push({hash:sha(token),userId:user.id,expires:Date.now()+30*86400000});return token}
function prune(){store.sessions=store.sessions.filter(s=>s.expires>Date.now())}
function rateLimited(ip){const time=Date.now();const a=attemptWindow.get(ip)||[];const recent=a.filter(t=>time-t<15*60*1000);recent.push(time);attemptWindow.set(ip,recent);return recent.length>25}
function body(req){return new Promise((resolve,reject)=>{let chunks=[],length=0;req.on('data',c=>{length+=c.length;if(length>MAX_BODY){reject({status:413,message:'That upload is too large'});req.destroy();return}chunks.push(c)});req.on('end',()=>{try{resolve(JSON.parse(Buffer.concat(chunks).toString()||'{}'))}catch(_){reject({status:400,message:'Invalid request data'})}});req.on('error',reject)})}
function freshFamily(displayName){return {family:displayName+' Family',people:[displayName],events:[],chores:[],wallet:[],meals:[],groceries:[],challenges:[],movies:[],gifts:[],activities:[],photos:[],memories:[],hunt:[],bets:[],supplies:[],notes:[],recipes:[],scores:[],category:'all'}}
function cleanFamily(d,old){if(!d||typeof d!=='object'||Array.isArray(d))return null;
const v={...old};for(const k of Object.keys(old)){if(Array.isArray(old[k])){if(!Array.isArray(d[k])||d[k].length>5000)return null;v[k]=d[k]}else if(typeof old[k]==='string'&&typeof d[k]==='string')v[k]=d[k].slice(0,120)}
if(!Array.isArray(v.people)||v.people.some(p=>typeof p!=='string'||p.length>32))return null;
return v}

const server=http.createServer(async(req,res)=>{
try{
const url=new URL(req.url,'http://localhost');
const p=url.pathname;
if(req.method==='GET'&&(p==='/'||p==='/index.html')){res.writeHead(200,{'content-type':'text/html; charset=utf-8','cache-control':'no-cache','x-content-type-options':'nosniff','referrer-policy':'same-origin','x-frame-options':'DENY','content-security-policy':"default-src 'self' data:; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"});return res.end(INDEX)}
if(p==='/favicon.ico'){res.writeHead(204);return res.end()}
if(p==='/api/config'&&req.method==='GET')return respond(res,200,{homebaseServer:true});
if(p==='/api/invite'&&req.method==='GET'){
const code=url.searchParams.get('code');const family=store.families.find(f=>f.inviteCode===code && code && code.length>10);
return family?respond(res,200,{family:family.db.family}):error(res,404,'Invalid or expired invitation');}
if(p==='/api/register'&&req.method==='POST'){
if(rateLimited(req.socket.remoteAddress))return error(res,429,'Too many attempts. Try again later.');
const data=await body(req);const username=String(data.username||'').trim().toLowerCase();const displayName=String(data.displayName||'').trim();const pass=data.password;
if(!/^[a-z0-9_]{3,20}$/.test(username))return error(res,400,'Username must be 3–20 letters, numbers, or underscores.');
if(displayName.length<1||displayName.length>32)return error(res,400,'Enter a name of 1–32 characters.');
if(!validPassword(pass))return error(res,400,'Use a password of 8–128 characters.');
if(store.users.some(u=>u.username===username))return error(res,409,'That username is taken. Try another.');
let family;
if(data.inviteCode){family=store.families.find(f=>f.inviteCode===data.inviteCode);if(!family)return error(res,404,'That invite link is no longer valid.');
if(store.users.some(u=>u.familyId===family.id&&u.displayName.toLowerCase()===displayName.toLowerCase()))return error(res,409,'Someone in the family already has that display name.');
} else {family={id:rand(16),inviteCode:rand(28),db:freshFamily(displayName),version:1};store.families.push(family)}
const u={id:rand(16),username,displayName,avatar:'😎',joined:new Date().toISOString(),triviaRight:0,triviaAttempts:0,solvedHunts:0,activity:[],familyId:family.id,salt:rand(24),hash:''};u.hash=hashPassword(pass,u.salt);store.users.push(u);
if(!family.db.people.includes(displayName))family.db.people.push(displayName);
family.version++;
const token=createSession(u);prune();persist();return respond(res,201,familyPayload(u,family,token));}
if(p==='/api/login'&&req.method==='POST'){
if(rateLimited(req.socket.remoteAddress))return error(res,429,'Too many attempts. Try again later.');
const data=await body(req);const user=store.users.find(u=>u.username===String(data.username||'').trim().toLowerCase());
if(!user||typeof data.password!=='string'||!passwordMatches(user,data.password))return error(res,401,'Incorrect username or password.');
const family=store.families.find(f=>f.id===user.familyId);if(!family)return error(res,404,'Family not found');
const token=createSession(user);prune();persist();return respond(res,200,familyPayload(user,family,token));}
if(p.startsWith('/api/')){
const auth=lookupToken(req);if(!auth)return error(res,401,'Session expired');
const {user,family,session}=auth;
if(p==='/api/state'&&req.method==='GET')return respond(res,200,familyPayload(user,family));
if(p==='/api/invites'&&req.method==='POST')return respond(res,200,{code:family.inviteCode});
if(p==='/api/invites/rotate'&&req.method==='POST'){family.inviteCode=rand(28);persist();return respond(res,200,{code:family.inviteCode})}
if(p==='/api/state'&&req.method==='PUT'){
const data=await body(req);
if(data.version!==family.version)return error(res,409,'Family changed on another device; reload before making more changes.');
const updated=cleanFamily(data.db,family.db);if(!updated)return error(res,400,'Invalid family data');
family.db=updated;family.version++;
const p=data.profile||{};
if(p.id===user.id){if(typeof p.avatar==='string'&&p.avatar.length<=12)user.avatar=p.avatar;
for(const key of ['triviaRight','triviaAttempts','solvedHunts'])if(Number.isSafeInteger(p[key])&&p[key]>=0)user[key]=p[key];
if(Array.isArray(p.activity))user.activity=p.activity.slice(0,120).map(a=>({id:String(a.id||'').slice(0,64),text:String(a.text||'').slice(0,300),at:String(a.at||'').slice(0,40),xp:Number(a.xp)||0}));
// Only the person who owns the profile can change its name.
if(typeof p.displayName==='string'&&p.displayName.length>0&&p.displayName.length<=32&& !store.users.some(u=>u.familyId===family.id&&u.id!==user.id&&u.displayName.toLowerCase()===p.displayName.toLowerCase()))user.displayName=p.displayName;}
persist();return respond(res,200,{version:family.version});}
if(p==='/api/password'&&req.method==='POST'){const d=await body(req);if(typeof d.current!=='string'||!passwordMatches(user,d.current))return error(res,400,'Incorrect current password');if(!validPassword(d.next))return error(res,400,'New password must be 8–128 characters');user.salt=rand(24);user.hash=hashPassword(d.next,user.salt);persist();return respond(res,200,{ok:true});}
if(p==='/api/logout'&&req.method==='POST'){store.sessions=store.sessions.filter(s=>s!==session);persist();return respond(res,200,{ok:true})}
return error(res,404,'Not found');}
return error(res,404,'Not found');
}catch(err){if(err.status)return error(res,err.status,err.message);console.error('Homebase error',err);if(!res.headersSent)error(res,500,'Server error');else res.end()}
});
server.listen(PORT,'0.0.0.0',()=>console.log(`Homebase running on http://localhost:${PORT}`));
