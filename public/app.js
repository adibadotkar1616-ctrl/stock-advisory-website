const $=s=>document.querySelector(s);

let token=localStorage.getItem('token'),state=null;

async function api(p,o={}){
  o.headers={
    ...(o.headers||{}),
    ...(token?{Authorization:'Bearer '+token}:{})
  };

  if(o.body&&typeof o.body!=='string'){
    o.headers['Content-Type']='application/json';
    o.body=JSON.stringify(o.body);
  }

  const r=await fetch(p,o);
  const d=await r.json();

  if(!r.ok)throw Error(d.error||'Request failed');

  return d;
}

function esc(x){
  return String(x??'').replace(/[&<>"']/g,c=>({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;',
    "'":'&#39;'
  }[c]));
}

function money(x){
  return '₹'+Number(x||0).toLocaleString('en-IN');
}


/* =========================
   NAVIGATION
========================= */

function nav(){

  $('#nav').innerHTML=token

    ? `<button onclick="logout()">Logout</button>`

    : `
      <button onclick="auth('login')">
        Client Login
      </button>

      <button onclick="adminAuth()">
        Admin Login
      </button>

      <button class="primary" onclick="auth('register')">
        Open Account
      </button>
    `;
}


/* =========================
   CLIENT LOGIN / REGISTER
========================= */

function auth(mode){

  $('#app').innerHTML=`

    <section class="auth">

      <div class="panel">

        <div class="eyebrow">
          SECURE CLIENT PORTAL
        </div>

        <h1>
          ${mode==='login'
            ? 'Welcome back'
            : 'Open your client account'}
        </h1>

        <form onsubmit="submitAuth(event,'${mode}')">

          ${
            mode==='register'
            ? `
              <input
                name="name"
                placeholder="Full name"
                required
              >
            `
            : ''
          }

          <input
            name="email"
            type="email"
            placeholder="Email address"
            required
          >

          <input
            name="password"
            type="password"
            placeholder="Password (8+ characters)"
            minlength="8"
            required
          >

          <button class="primary full" type="submit">
            ${mode==='login'
              ? 'Login'
              : 'Create account'}
          </button>

        </form>

        <p class="muted">

          ${
            mode==='login'
            ? 'New client?'
            : 'Already registered?'
          }

          <a
            href="#"
            onclick="auth('${
              mode==='login'
              ? 'register'
              : 'login'
            }');return false;"
          >
            ${
              mode==='login'
              ? 'Create an account'
              : 'Login'
            }
          </a>

        </p>

        <p class="muted">

          <a
            href="#"
            onclick="adminAuth();return false;"
          >
            Admin Login
          </a>

        </p>

      </div>

    </section>
  `;
}


/* =========================
   ADMIN LOGIN
========================= */

function adminAuth(){

  $('#app').innerHTML=`

    <section class="auth">

      <div class="panel">

        <div class="eyebrow">
          ADMIN PORTAL
        </div>

        <h1>
          Administrator Login
        </h1>

        <form onsubmit="submitAdminAuth(event)">

          <input
            name="email"
            type="email"
            placeholder="Admin email"
            required
          >

          <input
            name="password"
            type="password"
            placeholder="Admin password"
            required
          >

          <button
            class="primary full"
            type="submit"
          >
            Admin Login
          </button>

        </form>

        <p class="muted">

          <a
            href="#"
            onclick="home();return false;"
          >
            Back to website
          </a>

        </p>

      </div>

    </section>
  `;
}


/* =========================
   CLIENT AUTH SUBMIT
========================= */

async function submitAuth(e,m){

  e.preventDefault();

  try{

    const form=e.currentTarget;

    const x=Object.fromEntries(
      new FormData(form)
    );

    const d=await api(
      '/api/'+(
        m==='login'
        ? 'login'
        : 'register'
      ),
      {
        method:'POST',
        body:x
      }
    );

    token=d.token;

    localStorage.setItem(
      'token',
      token
    );

    await load();

  }catch(err){

    alert(err.message);

  }
}


/* =========================
   ADMIN AUTH SUBMIT
========================= */

async function submitAdminAuth(e){

  e.preventDefault();

  try{

    const form=e.currentTarget;

    const x=Object.fromEntries(
      new FormData(form)
    );

    const d=await api(
      '/api/login',
      {
        method:'POST',
        body:x
      }
    );

    token=d.token;

    localStorage.setItem(
      'token',
      token
    );

    await load();

  }catch(err){

    alert(err.message);

  }
}


/* =========================
   LOGOUT
========================= */

function logout(){

  token=null;

  state=null;

  localStorage.removeItem('token');

  nav();

  home();
}


/* =========================
   HOME PAGE
========================= */

function home(){

  $('#app').innerHTML=`

    <section class="hero">

      <div>

        <div class="eyebrow">
          RESEARCH • ADVISORY • CLIENT PORTAL
        </div>

        <h1>
          Make market decisions with a clearer process.
        </h1>

        <p>
          Research, recommendations, portfolio tracking,
          subscription plans, payments, notifications and KYC—
          inside one client platform.
        </p>

        <button
