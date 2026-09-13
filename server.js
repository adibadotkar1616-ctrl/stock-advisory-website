const http=require('http');
const fs=require('fs');
const path=require('path');
const crypto=require('crypto');
const {Pool}=require('pg');

const PORT=process.env.PORT||3000;
const SECRET=process.env.JWT_SECRET;
const ADMIN_EMAIL=(process.env.ADMIN_EMAIL||'').toLowerCase();
const ADMIN_PASSWORD=process.env.ADMIN_PASSWORD||'';
const DATABASE_URL=process.env.DATABASE_URL;
const ALLOWED_ORIGIN='https://stock-advisory-website.onrender.com';

// Manual bank-transfer payment details are read from Render environment variables.
const BANK_ACCOUNT_NAME=process.env.BANK_ACCOUNT_NAME||'';
const BANK_NAME=process.env.BANK_NAME||'';
const BANK_ACCOUNT_NUMBER=process.env.BANK_ACCOUNT_NUMBER||'';
const BANK_IFSC=process.env.BANK_IFSC||'';
const BANK_UPI_ID=process.env.BANK_UPI_ID||'';

const BREVO_API_KEY=process.env.BREVO_API_KEY||'';
const BREVO_SENDER_EMAIL=process.env.BREVO_SENDER_EMAIL||'';
const BREVO_SENDER_NAME=process.env.BREVO_SENDER_NAME||'Vertex Advisory';
const APP_ORIGIN=ALLOWED_ORIGIN;

// Basic login rate limiting: 5 failed attempts per IP/email within 15 minutes.
// This is intentionally in-memory; for multi-instance production, use a shared store.
const LOGIN_WINDOW_MS=15*60*1000;
const LOGIN_MAX_ATTEMPTS=5;
const loginAttempts=new Map();

function clientIp(req){
  return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim();
}
function loginKey(req,email){
  return clientIp(req)+'|'+String(email||'').toLowerCase();
}
function loginBlocked(req,email){
  const key=loginKey(req,email), now=Date.now();
  const item=loginAttempts.get(key);
  if(!item || now-item.first>=LOGIN_WINDOW_MS){
    loginAttempts.delete(key);
    return false;
  }
  return item.count>=LOGIN_MAX_ATTEMPTS;
}
function recordLoginFailure(req,email){
  const key=loginKey(req,email), now=Date.now();
  const item=loginAttempts.get(key);
  if(!item || now-item.first>=LOGIN_WINDOW_MS) loginAttempts.set(key,{count:1,first:now});
  else item.count++;
}
function clearLoginFailures(req,email){
  loginAttempts.delete(loginKey(req,email));
}
setInterval(()=>{
  const now=Date.now();
  for(const [key,item] of loginAttempts){
    if(now-item.first>=LOGIN_WINDOW_MS) loginAttempts.delete(key);
  }
},LOGIN_WINDOW_MS).unref();

if(!SECRET) throw new Error('JWT_SECRET environment variable is required');
if(!ADMIN_EMAIL||!ADMIN_PASSWORD) throw new Error('ADMIN_EMAIL and ADMIN_PASSWORD environment variables are required');
if(!DATABASE_URL) throw new Error('DATABASE_URL environment variable is required');

const pool=new Pool({
  connectionString:DATABASE_URL,
  ssl:{rejectUnauthorized:false}
});

const seedPlans=[
  {name:'Starter',price:999,period:'month',features:['Weekly research','Basic alerts','Email notifications']},
  {name:'Pro',price:2499,period:'month',features:['Daily research','Buy/Sell alerts','Model portfolio','Priority support']},
  {name:'Premium',price:4999,period:'month',features:['All Pro features','1:1 review calls','Advanced portfolio tracking']}
];

function hash(p){
  const s=crypto.randomBytes(16).toString('hex');
  const h=crypto.scryptSync(p,s,64).toString('hex');
  return s+':'+h;
}
function verify(p,x){
  try{
    const [s,h]=String(x).split(':');
    return crypto.timingSafeEqual(Buffer.from(h,'hex'),crypto.scryptSync(p,s,64));
  }catch{return false}
}
function b64(x){return Buffer.from(JSON.stringify(x)).toString('base64url')}
function token(u){
  const h=b64({alg:'HS256',typ:'JWT'});
  const p=b64({id:u.id,email:u.email,role:u.role,name:u.name,exp:Date.now()+7*864e5});
  const s=crypto.createHmac('sha256',SECRET).update(h+'.'+p).digest('base64url');
  return h+'.'+p+'.'+s;
}
function auth(req){
  const t=(req.headers.authorization||'').replace('Bearer ','');
  try{
    const [h,p,s]=t.split('.');
    const good=crypto.createHmac('sha256',SECRET).update(h+'.'+p).digest('base64url');
    if(s!==good)return null;
    const x=JSON.parse(Buffer.from(p,'base64url'));
    if(x.exp<Date.now())return null;
    return x;
  }catch{return null}
}
function body(req){
  return new Promise((resolve,reject)=>{
    let d='';
    req.on('data',c=>{
      d+=c;
      if(d.length>2e6) req.destroy();
    });
    req.on('end',()=>{
      try{resolve(d?JSON.parse(d):{})}catch{resolve({})}
    });
    req.on('error',reject);
  });
}
function send(res,code,data){
  res.writeHead(code,{
    'Content-Type':'application/json',
    'Access-Control-Allow-Origin':ALLOWED_ORIGIN,
    'Access-Control-Allow-Headers':'Content-Type,Authorization',
    'Access-Control-Allow-Methods':'GET,POST,OPTIONS'
  });
  res.end(JSON.stringify(data));
}
function publicUser(u){
  return {id:u.id,name:u.name,email:u.email,role:u.role,planId:u.plan_id||null};
}
async function notify(userId,title,message){
  await pool.query(
    'INSERT INTO notifications(user_id,title,message,read,created_at) VALUES($1,$2,$3,false,NOW())',
    [userId,title,message]
  );
}

async function sendEmail(to,subject,html){
  if(!BREVO_API_KEY||!BREVO_SENDER_EMAIL) throw new Error('Brevo email configuration is missing.');
  const r=await fetch('https://api.brevo.com/v3/smtp/email',{
    method:'POST',
    headers:{'accept':'application/json','api-key':BREVO_API_KEY,'content-type':'application/json'},
    body:JSON.stringify({sender:{name:BREVO_SENDER_NAME,email:BREVO_SENDER_EMAIL},to:[{email:to}],subject,htmlContent:html})
  });
  if(!r.ok){
    const text=await r.text();
    throw new Error('Brevo email send failed: '+text.slice(0,500));
  }
  return true;
}
function randomToken(){return crypto.randomBytes(32).toString('hex');}
function tokenHash(t){return crypto.createHash('sha256').update(String(t)).digest('hex');}
function escHtml(v){return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');}
function emailHtml(title,body,buttonText,buttonUrl){
  return `<!doctype html><html><body style="font-family:Arial,sans-serif;line-height:1.6;color:#111827;max-width:640px;margin:0 auto;padding:24px"><h2>${title}</h2><p>${body}</p>${buttonUrl?`<p><a href="${buttonUrl}" style="display:inline-block;padding:12px 18px;background:#111827;color:#fff;text-decoration:none;border-radius:8px">${buttonText}</a></p>`:''}<p style="color:#6b7280;font-size:13px">If you did not request this, you can safely ignore this email.</p></body></html>`;
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'client',
      plan_id INTEGER
    );
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS verify_expires TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_token_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS reset_expires TIMESTAMPTZ;
    CREATE TABLE IF NOT EXISTS plans(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price INTEGER NOT NULL,
      period TEXT NOT NULL,
      features JSONB NOT NULL DEFAULT '[]'::jsonb
    );
    CREATE TABLE IF NOT EXISTS research(
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT NOT NULL,
      body TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS calls(
      id SERIAL PRIMARY KEY,
      user_id INTEGER,
      date TEXT,
      time TEXT,
      topic TEXT,
      status TEXT NOT NULL DEFAULT 'scheduled'
    );
    CREATE TABLE IF NOT EXISTS recommendations(
      id SERIAL PRIMARY KEY,
      symbol TEXT,
      action TEXT,
      entry TEXT,
      target TEXT,
      stop_loss TEXT,
      risk TEXT,
      note TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS portfolios(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      symbol TEXT,
      quantity NUMERIC DEFAULT 0,
      avg_price NUMERIC DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payments(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      plan_id INTEGER,
      amount INTEGER,
      status TEXT NOT NULL DEFAULT 'pending',
      method TEXT,
      details JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    ALTER TABLE payments ADD COLUMN IF NOT EXISTS details JSONB NOT NULL DEFAULT '{}'::jsonb;
    CREATE TABLE IF NOT EXISTS notifications(
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL,
      title TEXT,
      message TEXT,
      read BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS kyc(
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'not_submitted',
      documents JSONB NOT NULL DEFAULT '[]'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const planCount=await pool.query('SELECT COUNT(*)::int AS count FROM plans');
  if(planCount.rows[0].count===0){
    for(const p of seedPlans){
      await pool.query(
        'INSERT INTO plans(name,price,period,features) VALUES($1,$2,$3,$4::jsonb)',
        [p.name,p.price,p.period,JSON.stringify(p.features)]
      );
    }
  }

  const adminResult=await pool.query('SELECT * FROM users WHERE role=$1 ORDER BY id LIMIT 1',['admin']);
  if(adminResult.rowCount===0){
    await pool.query(
      'INSERT INTO users(name,email,password,role,email_verified) VALUES($1,$2,$3,$4,true)',
      ['Administrator',ADMIN_EMAIL,hash(ADMIN_PASSWORD),'admin']
    );
  }else{
    const admin=adminResult.rows[0];
    if(admin.email!==ADMIN_EMAIL || !verify(ADMIN_PASSWORD,admin.password)){
      await pool.query('UPDATE users SET email=$1,password=$2,email_verified=true WHERE id=$3',[ADMIN_EMAIL,hash(ADMIN_PASSWORD),admin.id]);
    }
  }
}

async function api(req,res){
  const url=new URL(req.url,'http://localhost');
  const p=url.pathname;

  if(req.method==='OPTIONS'){
    res.writeHead(204,{
      'Access-Control-Allow-Origin':ALLOWED_ORIGIN,
      'Access-Control-Allow-Headers':'Content-Type,Authorization',
      'Access-Control-Allow-Methods':'GET,POST,OPTIONS'
    });
    return res.end();
  }

  if(p==='/api/register'&&req.method==='POST'){
    const x=await body(req);
    const email=String(x.email||'').toLowerCase().trim();
    if(!x.name||!email||!x.password||x.password.length<8)
      return send(res,400,{error:'Name, email and password (8+ characters) are required.'});

    const exists=await pool.query('SELECT id FROM users WHERE email=$1',[email]);
    if(exists.rowCount)return send(res,409,{error:'Email already registered.'});

    const verifyToken=randomToken();
    const verifyHash=tokenHash(verifyToken);
    const r=await pool.query(
      'INSERT INTO users(name,email,password,role,email_verified,verify_token_hash,verify_expires) VALUES($1,$2,$3,$4,false,$5,NOW()+INTERVAL \'24 hours\') RETURNING *',
      [x.name,email,hash(x.password),'client',verifyHash]
    );
    const u=r.rows[0];

    await pool.query(
      'INSERT INTO kyc(user_id,status,documents) VALUES($1,$2,$3::jsonb)',
      [u.id,'not_submitted','[]']
    );
    await notify(u.id,'Welcome to Vertex Advisory','Please verify your email address to activate your client account.');

    const verifyUrl=`${APP_ORIGIN}/api/verify-email?token=${encodeURIComponent(verifyToken)}`;
    try{
      await sendEmail(email,'Verify your Vertex Advisory email',emailHtml('Verify your email','Welcome to Vertex Advisory. Please verify your email address to activate your account.','Verify Email',verifyUrl));
    }catch(err){
      console.error(err);
      return send(res,201,{ok:true,emailVerificationRequired:true,message:'Account created, but the verification email could not be sent. Please use password reset or contact support after email service is checked.'});
    }
    return send(res,201,{ok:true,emailVerificationRequired:true,message:'Account created. Please check your email and verify your address before logging in.'});
  }

  if(p==='/api/login'&&req.method==='POST'){
    const x=await body(req);
    const email=String(x.email||'').toLowerCase();
    if(loginBlocked(req,email))
      return send(res,429,{error:'Too many failed login attempts. Please try again in 15 minutes.'});

    const r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    const u=r.rows[0];
    if(!u||!verify(x.password||'',u.password)){
      recordLoginFailure(req,email);
      return send(res,401,{error:'Invalid email or password.'});
    }
    if(u.role!=='admin' && u.email_verified===false)
      return send(res,403,{error:'Please verify your email before logging in. Check your inbox for the verification link.'});
    clearLoginFailures(req,email);
    return send(res,200,{token:token(u),user:publicUser(u)});
  }

  if(p==='/api/verify-email'&&req.method==='GET'){
    const t=String(url.searchParams.get('token')||'');
    if(!t)return send(res,400,{error:'Verification token is required.'});
    const r=await pool.query('SELECT id,email FROM users WHERE verify_token_hash=$1 AND verify_expires>NOW()',[tokenHash(t)]);
    if(!r.rowCount){
      res.writeHead(400,{'Content-Type':'text/html; charset=utf-8'});
      return res.end('<h2>Verification link is invalid or expired.</h2><p>Please request a new verification email or contact support.</p>');
    }
    await pool.query('UPDATE users SET email_verified=true,verify_token_hash=NULL,verify_expires=NULL WHERE id=$1',[r.rows[0].id]);
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    return res.end('<h2>Email verified successfully.</h2><p>Your Vertex Advisory account is now active. You can return to the website and log in.</p>');
  }

  if(p==='/api/forgot-password'&&req.method==='POST'){
    const x=await body(req);
    const email=String(x.email||'').toLowerCase().trim();
    if(!email)return send(res,400,{error:'Email is required.'});
    const r=await pool.query('SELECT id,name,email FROM users WHERE email=$1',[email]);
    // Always return the same response to avoid revealing registered accounts.
    if(r.rowCount){
      const resetToken=randomToken();
      await pool.query('UPDATE users SET reset_token_hash=$1,reset_expires=NOW()+INTERVAL \'30 minutes\' WHERE id=$2',[tokenHash(resetToken),r.rows[0].id]);
      const resetUrl=`${APP_ORIGIN}/api/reset-password?token=${encodeURIComponent(resetToken)}`;
      try{
        await sendEmail(email,'Reset your Vertex Advisory password',emailHtml('Reset your password','We received a request to reset your Vertex Advisory password. This link expires in 30 minutes.','Reset Password',resetUrl));
      }catch(err){console.error(err);}
    }
    return send(res,200,{ok:true,message:'If an account exists for that email, a password reset link has been sent.'});
  }

  if(p==='/api/reset-password'&&req.method==='GET'){
    const t=String(url.searchParams.get('token')||'');
    if(!t){res.writeHead(400,{'Content-Type':'text/html; charset=utf-8'});return res.end('<h2>Invalid reset link.</h2>');}
    const r=await pool.query('SELECT id FROM users WHERE reset_token_hash=$1 AND reset_expires>NOW()',[tokenHash(t)]);
    if(!r.rowCount){res.writeHead(400,{'Content-Type':'text/html; charset=utf-8'});return res.end('<h2>Reset link is invalid or expired.</h2><p>Please request a new password reset email.</p>');}
    const safeToken=escHtml(t);
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    return res.end(`<!doctype html><html><body style="font-family:Arial,sans-serif;max-width:420px;margin:40px auto;padding:20px"><h2>Reset Vertex Advisory password</h2><form method="POST" action="/api/reset-password"><input type="hidden" name="token" value="${safeToken}"><label>New password</label><br><input name="password" type="password" minlength="8" required style="width:100%;padding:10px;margin:8px 0 16px"><button type="submit" style="padding:10px 16px">Reset Password</button></form></body></html>`);
  }

  if(p==='/api/reset-password'&&req.method==='POST'){
    let x={};
    const ct=String(req.headers['content-type']||'');
    if(ct.includes('application/json')) x=await body(req);
    else{
      const raw=await new Promise((resolve,reject)=>{let d='';req.on('data',c=>d+=c);req.on('end',()=>resolve(d));req.on('error',reject);});
      const params=new URLSearchParams(raw); x=Object.fromEntries(params.entries());
    }
    const t=String(x.token||'');
    const password=String(x.password||'');
    if(!t||password.length<8)return send(res,400,{error:'Valid reset token and password (8+ characters) are required.'});
    const r=await pool.query('SELECT id FROM users WHERE reset_token_hash=$1 AND reset_expires>NOW()',[tokenHash(t)]);
    if(!r.rowCount)return send(res,400,{error:'Reset link is invalid or expired.'});
    await pool.query('UPDATE users SET password=$1,reset_token_hash=NULL,reset_expires=NULL WHERE id=$2',[hash(password),r.rows[0].id]);
    res.writeHead(200,{'Content-Type':'text/html; charset=utf-8'});
    return res.end('<h2>Password reset successful.</h2><p>Your password has been changed. You can now return to Vertex Advisory and log in.</p>');
  }

  const me=auth(req);
  if(!me)return send(res,401,{error:'Authentication required.'});

  const ur=await pool.query('SELECT * FROM users WHERE id=$1',[me.id]);
  const u=ur.rows[0];
  if(!u)return send(res,401,{error:'Account not found.'});

  if(p==='/api/dashboard'&&req.method==='GET'){
    const [plans,research,calls,recs,portfolio,payments,notifications,kyc,currentPlan]=await Promise.all([
      pool.query('SELECT id,name,price,period,features FROM plans ORDER BY id'),
      pool.query('SELECT id,title,category,body,created_at AS "createdAt" FROM research ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",date,time,topic,status FROM calls WHERE user_id=$1 OR user_id IS NULL ORDER BY id DESC',[u.id]),
      pool.query('SELECT id,symbol,action,entry,target,stop_loss AS "stopLoss",risk,note,created_at AS "createdAt" FROM recommendations ORDER BY id DESC'),
      pool.query('SELECT id,symbol,quantity,avg_price AS "avgPrice",updated_at AS "updatedAt" FROM portfolios WHERE user_id=$1 ORDER BY id DESC',[u.id]),
      pool.query('SELECT id,user_id AS "userId",plan_id AS "planId",amount,status,method,details,created_at AS "createdAt" FROM payments WHERE user_id=$1 ORDER BY id DESC',[u.id]),
      pool.query('SELECT id,user_id AS "userId",title,message,read,created_at AS "createdAt" FROM notifications WHERE user_id=$1 ORDER BY id DESC',[u.id]),
      pool.query('SELECT id,user_id AS "userId",status,documents,updated_at AS "updatedAt" FROM kyc WHERE user_id=$1',[u.id]),
      pool.query('SELECT id,name,price,period,features FROM plans WHERE id=$1',[u.plan_id])
    ]);
    return send(res,200,{
      user:publicUser(u),
      plan:currentPlan.rows[0]||null,
      plans:plans.rows,
      research:research.rows,
      calls:calls.rows,
      recommendations:recs.rows,
      portfolio:portfolio.rows,
      payments:payments.rows,
      notifications:notifications.rows,
      kyc:kyc.rows[0]||null
    });
  }

  if(p==='/api/admin'&&req.method==='GET'){
    if(u.role!=='admin')return send(res,403,{error:'Admin only.'});
    const [users,plans,research,calls,recs,portfolio,payments,notifications,kyc]=await Promise.all([
      pool.query('SELECT id,name,email,role,plan_id AS "planId" FROM users ORDER BY id'),
      pool.query('SELECT id,name,price,period,features FROM plans ORDER BY id'),
      pool.query('SELECT id,title,category,body,created_at AS "createdAt" FROM research ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",date,time,topic,status FROM calls ORDER BY id DESC'),
      pool.query('SELECT id,symbol,action,entry,target,stop_loss AS "stopLoss",risk,note,created_at AS "createdAt" FROM recommendations ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",symbol,quantity,avg_price AS "avgPrice",updated_at AS "updatedAt" FROM portfolios ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",plan_id AS "planId",amount,status,method,details,created_at AS "createdAt" FROM payments ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",title,message,read,created_at AS "createdAt" FROM notifications ORDER BY id DESC'),
      pool.query('SELECT id,user_id AS "userId",status,documents,updated_at AS "updatedAt" FROM kyc ORDER BY id DESC')
    ]);
    return send(res,200,{
      users:users.rows,
      plans:plans.rows,
      research:research.rows,
      calls:calls.rows,
      recommendations:recs.rows,
      portfolio:portfolio.rows,
      payments:payments.rows,
      notifications:notifications.rows,
      kyc:kyc.rows
    });
  }

  if(u.role!=='admin'&&p.startsWith('/api/admin'))
    return send(res,403,{error:'Admin only.'});

  if(p==='/api/bank-payment'&&req.method==='POST'){
    const x=await body(req);
    const planId=Number(x.planId);
    const utr=String(x.utr||'').trim();
    if(!planId||!utr||utr.length<6||utr.length>50)
      return send(res,400,{error:'Valid plan and UTR/transaction reference are required.'});
    const pr=await pool.query('SELECT * FROM plans WHERE id=$1',[planId]);
    if(!pr.rowCount)return send(res,400,{error:'Invalid plan.'});
    const duplicate=await pool.query("SELECT id FROM payments WHERE method=$1 AND details->>'utr'=$2 LIMIT 1",['bank_transfer',utr]);
    if(duplicate.rowCount)return send(res,409,{error:'This UTR/transaction reference has already been submitted.'});
    const r=await pool.query(
      `INSERT INTO payments(user_id,plan_id,amount,status,method,details) VALUES($1,$2,$3,$4,$5,$6::jsonb) RETURNING id,plan_id AS "planId",amount,status,method,details,created_at AS "createdAt"`,
      [u.id,planId,pr.rows[0].price,'pending','bank_transfer',JSON.stringify({utr})]
    );
    await notify(u.id,'Bank transfer submitted',`Your payment reference ${utr} has been submitted for verification.`);
    return send(res,201,{ok:true,payment:r.rows[0]});
  }

  if(p==='/api/payment-info'&&req.method==='GET'){
    return send(res,200,{
      accountName:BANK_ACCOUNT_NAME,
      bankName:BANK_NAME,
      accountNumber:BANK_ACCOUNT_NUMBER,
      ifsc:BANK_IFSC,
      upiId:BANK_UPI_ID
    });
  }

  if(p==='/api/plan'&&req.method==='POST'){
    const x=await body(req);
    const planId=Number(x.planId);
    const pr=await pool.query('SELECT * FROM plans WHERE id=$1',[planId]);
    if(!pr.rowCount)return send(res,400,{error:'Invalid plan.'});
    await pool.query(
      'INSERT INTO payments(user_id,plan_id,amount,status,method) VALUES($1,$2,$3,$4,$5)',
      [u.id,planId,pr.rows[0].price,'pending',x.method||'manual']
    );
    await notify(u.id,'Plan selected','Your subscription request is pending payment confirmation.');
    return send(res,200,{ok:true});
  }

  if(p==='/api/kyc'&&req.method==='POST'){
    const x=await body(req);
    const status=x.status||'submitted';
    const documents=x.documents||[];
    const r=await pool.query(
      `INSERT INTO kyc(user_id,status,documents,updated_at)
       VALUES($1,$2,$3::jsonb,NOW())
       ON CONFLICT(user_id) DO UPDATE SET status=EXCLUDED.status,documents=EXCLUDED.documents,updated_at=NOW()
       RETURNING id,user_id AS "userId",status,documents,updated_at AS "updatedAt"`,
      [u.id,status,JSON.stringify(documents)]
    );
    await notify(u.id,'KYC submitted','Your KYC information has been submitted for review.');
    return send(res,200,{kyc:r.rows[0]});
  }

  if(p==='/api/portfolio'&&req.method==='POST'){
    const x=await body(req);
    const r=await pool.query(
      'INSERT INTO portfolios(user_id,symbol,quantity,avg_price,updated_at) VALUES($1,$2,$3,$4,NOW()) RETURNING id',
      [u.id,x.symbol,Number(x.quantity)||0,Number(x.avgPrice)||0]
    );
    return send(res,201,{ok:true,id:r.rows[0].id});
  }

  if(p==='/api/admin/research'&&req.method==='POST'){
    const x=await body(req);
    await pool.query(
      'INSERT INTO research(title,category,body) VALUES($1,$2,$3)',
      [x.title,x.category||'Research',x.body||'']
    );
    return send(res,201,{ok:true});
  }

  if(p==='/api/admin/recommendation'&&req.method==='POST'){
    const x=await body(req);
    await pool.query(
      'INSERT INTO recommendations(symbol,action,entry,target,stop_loss,risk,note) VALUES($1,$2,$3,$4,$5,$6,$7)',
      [x.symbol,x.action,x.entry,x.target,x.stopLoss,x.risk||'Medium',x.note||'']
    );
    const clients=await pool.query("SELECT id FROM users WHERE role='client'");
    for(const c of clients.rows)
      await notify(c.id,'New market recommendation',`${x.action} ${x.symbol} — target ${x.target||'N/A'}`);
    return send(res,201,{ok:true});
  }

  if(p==='/api/admin/call'&&req.method==='POST'){
    const x=await body(req);
    const userId=x.userId?Number(x.userId):null;
    await pool.query(
      'INSERT INTO calls(user_id,date,time,topic,status) VALUES($1,$2,$3,$4,$5)',
      [userId,x.date,x.time,x.topic,'scheduled']
    );
    if(userId)await notify(userId,'Advisory call scheduled',`${x.date} ${x.time} — ${x.topic}`);
    return send(res,201,{ok:true});
  }

  if(p==='/api/admin/payment'&&req.method==='POST'){
    const x=await body(req);
    const paymentId=Number(x.id);
    const status=String(x.status||'paid').toLowerCase();
    if(!paymentId || !['pending','paid','rejected'].includes(status))
      return send(res,400,{error:'Valid payment ID and status are required.'});
    const r=await pool.query('SELECT * FROM payments WHERE id=$1',[paymentId]);
    if(!r.rowCount)return send(res,404,{error:'Payment not found.'});
    await pool.query('UPDATE payments SET status=$1 WHERE id=$2',[status,paymentId]);
    if(status==='paid'){
      await pool.query('UPDATE users SET plan_id=$1 WHERE id=$2',[r.rows[0].plan_id,r.rows[0].user_id]);
      await notify(r.rows[0].user_id,'Payment confirmed','Your subscription payment has been verified and marked as paid.');
    } else if(status==='rejected'){
      await notify(r.rows[0].user_id,'Payment rejected','Your submitted payment could not be verified. Please contact support or submit a valid payment reference.');
    }
    return send(res,200,{ok:true});
  }

  if(p==='/api/admin/kyc'&&req.method==='POST'){
    const x=await body(req);
    const r=await pool.query('SELECT * FROM kyc WHERE id=$1',[Number(x.id)]);
    if(!r.rowCount)return send(res,404,{error:'KYC not found.'});
    await pool.query('UPDATE kyc SET status=$1,updated_at=NOW() WHERE id=$2',[x.status,Number(x.id)]);
    await notify(r.rows[0].user_id,'KYC status updated',`Your KYC status is now ${x.status}.`);
    return send(res,200,{ok:true});
  }

  if(p==='/api/admin/notification'&&req.method==='POST'){
    const x=await body(req);
    let recipients=[];
    if(x.userId)recipients=[Number(x.userId)];
    else{
      const clients=await pool.query("SELECT id FROM users WHERE role='client'");
      recipients=clients.rows.map(c=>c.id);
    }
    for(const id of recipients)await notify(id,x.title,x.message);
    return send(res,201,{ok:true});
  }

  if(p==='/api/admin/plan'&&req.method==='POST'){
    const x=await body(req);
    const features=String(x.features||'').split(',').map(s=>s.trim()).filter(Boolean);
    await pool.query(
      'INSERT INTO plans(name,price,period,features) VALUES($1,$2,$3,$4::jsonb)',
      [x.name,Number(x.price),x.period||'month',JSON.stringify(features)]
    );
    return send(res,201,{ok:true});
  }

  return send(res,404,{error:'Not found'});
}

const server=http.createServer(async(req,res)=>{
  try{
    if(req.url.startsWith('/api/'))return await api(req,res);
    let file=req.url==='/'?'/index.html':req.url;
    file=path.normalize(file).replace(/^\.\.(\/|\\)/,'');
    const publicDir=path.join(__dirname,'public');
    const fp=path.join(publicDir,file);
    if(!fp.startsWith(publicDir))return send(res,403,{error:'Forbidden'});
    fs.readFile(fp,(e,d)=>{
      if(e){res.writeHead(404);return res.end('Not found')}
      const ext=path.extname(fp);
      const ct={'.html':'text/html','.js':'text/javascript','.css':'text/css','.svg':'image/svg+xml'}[ext]||'text/plain';
      res.writeHead(200,{'Content-Type':ct});
      res.end(d);
    });
  }catch(e){
    console.error(e);
    send(res,500,{error:'Server error.'});
  }
});

initDb()
  .then(()=>server.listen(PORT,'0.0.0.0',()=>console.log(`Vertex Advisory portal running on port ${PORT}`)))
  .catch(e=>{console.error('Database initialization failed:',e);process.exit(1)});
