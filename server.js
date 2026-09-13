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
  return {id:u.id,name:u.name,email:u.email,role:u.role,planId:u.plan_id||null,active:u.active!==false};
}

function otpHash(email,otp){
  return crypto.createHmac('sha256',SECRET).update(String(email).toLowerCase()+'|'+String(otp)).digest('hex');
}
function makeOtp(){ return String(crypto.randomInt(0,1000000)).padStart(6,'0'); }
async function sendEmail(to,subject,html){
  if(!BREVO_API_KEY||!BREVO_SENDER_EMAIL) throw new Error('Brevo email configuration is missing.');
  const r=await fetch('https://api.brevo.com/v3/smtp/email',{
    method:'POST',
    headers:{accept:'application/json','api-key':BREVO_API_KEY,'content-type':'application/json'},
    body:JSON.stringify({sender:{name:BREVO_SENDER_NAME,email:BREVO_SENDER_EMAIL},to:[{email:to}],subject,htmlContent:html})
  });
  if(!r.ok){ const t=await r.text(); throw new Error('Brevo email failed: '+t.slice(0,300)); }
}
async function sendOtpEmail(email,name,otp){
  const html=`<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:24px">
    <h2 style="margin-bottom:8px">Vertex Advisory</h2>
    <p>Hello ${String(name||'there').replace(/[<>]/g,'')},</p>
    <p>Your email verification code is:</p>
    <div style="font-size:32px;font-weight:700;letter-spacing:8px;padding:18px 0">${otp}</div>
    <p>This code expires in <b>10 minutes</b>. Do not share it with anyone.</p>
    <p>If you did not create this account, you can ignore this email.</p>
  </div>`;
  await sendEmail(email,'Your Vertex Advisory verification OTP',html);
}

async function notify(userId,title,message){
  await pool.query(
    'INSERT INTO notifications(user_id,title,message,read,created_at) VALUES($1,$2,$3,false,NOW())',
    [userId,title,message]
  );
}

async function initDb(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users(
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'client',
      plan_id INTEGER,
      active BOOLEAN NOT NULL DEFAULT true
    );
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
    ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT true;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_otp_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_otp_expires TIMESTAMPTZ;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS email_otp_attempts INTEGER NOT NULL DEFAULT 0;
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
      'INSERT INTO users(name,email,password,role) VALUES($1,$2,$3,$4)',
      ['Administrator',ADMIN_EMAIL,hash(ADMIN_PASSWORD),'admin']
    );
  }else{
    const admin=adminResult.rows[0];
    if(admin.email!==ADMIN_EMAIL || !verify(ADMIN_PASSWORD,admin.password)){
      await pool.query('UPDATE users SET email=$1,password=$2 WHERE id=$3',[ADMIN_EMAIL,hash(ADMIN_PASSWORD),admin.id]);
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
    const email=String(x.email||'').toLowerCase();
    if(!x.name||!email||!x.password||x.password.length<8)
      return send(res,400,{error:'Name, email and password (8+ characters) are required.'});

    const exists=await pool.query('SELECT id FROM users WHERE email=$1',[email]);
    if(exists.rowCount)return send(res,409,{error:'Email already registered.'});

    const otp=makeOtp();
    const r=await pool.query(
      'INSERT INTO users(name,email,password,role,email_verified,email_otp_hash,email_otp_expires,email_otp_attempts) VALUES($1,$2,$3,$4,false,$5,NOW()+INTERVAL \'10 minutes\',0) RETURNING *',
      [x.name,email,hash(x.password),'client',otpHash(email,otp)]
    );
    const u=r.rows[0];

    await pool.query(
      'INSERT INTO kyc(user_id,status,documents) VALUES($1,$2,$3::jsonb)',
      [u.id,'not_submitted','[]']
    );
    await notify(u.id,'Welcome to Vertex Advisory','Verify your email with the 6-digit OTP sent to your inbox.');
    try{
      await sendOtpEmail(email,x.name,otp);
    }catch(e){
      console.error('OTP email failed:',e.message);
      return send(res,502,{error:'Account was created but the verification email could not be sent. Please check Brevo configuration and use Resend OTP.'});
    }
    return send(res,201,{ok:true,emailVerificationRequired:true,message:'A 6-digit verification OTP has been sent to your email.'});
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
    clearLoginFailures(req,email);
    if(u.active===false)return send(res,403,{error:'Your account is currently inactive. Please contact support.'});
    if(u.role!=='admin' && u.email_verified===false)
      return send(res,403,{error:'Please verify your email first. Enter the 6-digit OTP sent to your inbox.'});
    return send(res,200,{token:token(u),user:publicUser(u)});
  }

  if((p==='/api/verify-otp'||p==='/api/verify-email-otp')&&req.method==='POST'){
    const x=await body(req);
    const email=String(x.email||'').toLowerCase();
    const otp=String(x.otp||'').trim();
    if(!email||!/^[0-9]{6}$/.test(otp))return send(res,400,{error:'Enter the 6-digit OTP sent to your email.'});
    const r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    const u=r.rows[0];
    if(!u)return send(res,404,{error:'Account not found.'});
    if(u.email_verified!==false)return send(res,200,{ok:true,message:'Email is already verified.'});
    if(u.email_otp_expires && new Date(u.email_otp_expires)<new Date())return send(res,400,{error:'OTP has expired. Please request a new OTP.'});
    if((u.email_otp_attempts||0)>=5)return send(res,429,{error:'Too many incorrect OTP attempts. Please request a new OTP.'});
    if(u.email_otp_hash!==otpHash(email,otp)){
      await pool.query('UPDATE users SET email_otp_attempts=email_otp_attempts+1 WHERE id=$1',[u.id]);
      return send(res,400,{error:'Incorrect OTP. Please try again.'});
    }
    const fresh=(await pool.query('UPDATE users SET email_verified=true,email_otp_hash=NULL,email_otp_expires=NULL,email_otp_attempts=0 WHERE id=$1 RETURNING *',[u.id])).rows[0];
    await notify(u.id,'Email verified','Your email has been successfully verified. You can now log in.');
    return send(res,200,{ok:true,message:'Email verified successfully. You can now log in.',user:publicUser(fresh)});
  }

  if(p==='/api/resend-otp'&&req.method==='POST'){
    const x=await body(req);
    const email=String(x.email||'').toLowerCase();
    if(!email)return send(res,400,{error:'Email is required.'});
    const r=await pool.query('SELECT * FROM users WHERE email=$1',[email]);
    const u=r.rows[0];
    if(!u)return send(res,404,{error:'Account not found.'});
    if(u.email_verified!==false)return send(res,200,{ok:true,message:'Email is already verified.'});
    const otp=makeOtp();
    await pool.query('UPDATE users SET email_otp_hash=$1,email_otp_expires=NOW()+INTERVAL \'10 minutes\',email_otp_attempts=0 WHERE id=$2',[otpHash(email,otp),u.id]);
    try{await sendOtpEmail(email,u.name,otp);}catch(e){console.error('Resend OTP failed:',e.message);return send(res,502,{error:'Unable to send OTP email. Please check Brevo configuration.'});}
    return send(res,200,{ok:true,message:'A new 6-digit OTP has been sent.'});
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
      pool.query('SELECT id,name,email,role,plan_id AS "planId",active FROM users ORDER BY id'),
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

  if(p==='/api/admin/user'&&req.method==='POST'){
    const x=await body(req);
    const userId=Number(x.id);
    if(!userId)return send(res,400,{error:'Valid user ID is required.'});
    const target=await pool.query('SELECT * FROM users WHERE id=$1',[userId]);
    if(!target.rowCount)return send(res,404,{error:'User not found.'});
    if(target.rows[0].role==='admin')return send(res,400,{error:'Admin account cannot be changed here.'});
    if(x.active!==undefined){
      const active=x.active===true||x.active==='true';
      await pool.query('UPDATE users SET active=$1 WHERE id=$2',[active,userId]);
      await notify(userId,'Account status updated',active?'Your account has been activated.':'Your account has been deactivated. Please contact support if you need assistance.');
    }
    if(x.planId!==undefined){
      const planId=x.planId===null||x.planId===''?null:Number(x.planId);
      if(planId!==null){const pr=await pool.query('SELECT id FROM plans WHERE id=$1',[planId]);if(!pr.rowCount)return send(res,400,{error:'Invalid plan.'});}
      await pool.query('UPDATE users SET plan_id=$1 WHERE id=$2',[planId,userId]);
      await notify(userId,'Subscription updated',planId===null?'Your subscription plan has been removed.':'Your subscription plan has been updated by Vertex Advisory.');
    }
    const fresh=await pool.query('SELECT id,name,email,role,plan_id AS "planId",active FROM users WHERE id=$1',[userId]);
    return send(res,200,{ok:true,user:fresh.rows[0]});
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
