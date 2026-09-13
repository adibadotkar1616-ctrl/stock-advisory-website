const state = {
  token: localStorage.getItem('vertex_token') || '',
  user: null,
  data: null
};

const app = document.getElementById('app');

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };

  if (state.token) headers.Authorization = `Bearer ${state.token}`;

  if (options.body && typeof options.body !== 'string') {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const res = await fetch(path, { ...options, headers });

  let data = {};
  try {
    data = await res.json();
  } catch {}

  if (!res.ok) {
    throw new Error(data.error || data.message || `Request failed (${res.status})`);
  }

  return data;
}

function setToken(token) {
  state.token = token || '';
  if (state.token) localStorage.setItem('vertex_token', state.token);
  else localStorage.removeItem('vertex_token');
}

function logout() {
  setToken('');
  state.user = null;
  state.data = null;
  home();
}

function nav() {
  return `
    <nav class="nav">
      <div class="brand" onclick="home()">Vertex Advisory</div>
      <div class="nav-links">
        ${state.user ? `
          <button onclick="renderClient()">Dashboard</button>
          <button onclick="logout()">Logout</button>
        ` : `
          <button onclick="auth('login')">Client Login</button>
          <button onclick="adminAuth()">Admin Login</button>
          <button onclick="auth('register')">Open Account</button>
        `}
      </div>
    </nav>
  `;
}

function home() {
  app.innerHTML = `
    ${nav()}
    <main class="hero">
      <div class="hero-content">
        <h1>Vertex Advisory</h1>
        <p>Professional stock research, market insights, recommendations and portfolio guidance.</p>
        <div class="hero-buttons">
          <button class="primary" onclick="auth('login')">Client Login</button>
          <button class="secondary" onclick="adminAuth()">Admin Login</button>
          <button class="secondary" onclick="auth('register')">Open Account</button>
        </div>
      </div>
    </main>
  `;
}

function auth(mode) {
  const isLogin = mode === 'login';

  app.innerHTML = `
    ${nav()}
    <main class="page">
      <div class="card auth-card">
        <h2>${isLogin ? 'Client Login' : 'Create Your Account'}</h2>
        <form onsubmit="submitAuth(event, '${mode}')">
          ${!isLogin ? `
            <label>Full Name</label>
            <input type="text" name="name" required placeholder="Enter your full name" />
          ` : ''}
          <label>Email</label>
          <input type="email" name="email" required placeholder="Enter email address" />
          <label>Password</label>
          <input type="password" name="password" required placeholder="Enter password" />
          ${!isLogin ? `
            <label>Mobile Number</label>
            <input type="tel" name="phone" placeholder="Enter mobile number" />
          ` : ''}
          <button class="primary" type="submit">${isLogin ? 'Login' : 'Create Account'}</button>
        </form>
        <div class="auth-switch">
          ${isLogin ? `
            <span>Don't have an account?</span>
            <button onclick="auth('register')">Create Account</button>
          ` : `
            <span>Already have an account?</span>
            <button onclick="auth('login')">Login</button>
          `}
        </div>
      </div>
    </main>
  `;
}

function adminAuth() {
  app.innerHTML = `
    ${nav()}
    <main class="page">
      <div class="card auth-card">
        <h2>Admin Login</h2>
        <p class="muted">Authorized Vertex Advisory administrators only.</p>
        <form onsubmit="submitAdminAuth(event)">
          <label>Admin Email</label>
          <input type="email" name="email" required placeholder="Enter admin email" />
          <label>Password</label>
          <input type="password" name="password" required placeholder="Enter admin password" />
          <button class="primary" type="submit">Admin Login</button>
        </form>
        <div class="auth-switch">
          <button onclick="auth('login')">Back to Client Login</button>
        </div>
      </div>
    </main>
  `;
}

async function submitAuth(e, mode) {
  e.preventDefault();
  const form = e.currentTarget;

  if (!(form instanceof HTMLFormElement)) {
    alert('Unable to read the form. Please refresh the page.');
    return;
  }

  const x = Object.fromEntries(new FormData(form).entries());

  try {
    const result = await api(mode === 'login' ? '/api/login' : '/api/register', {
      method: 'POST',
      body: x
    });

    if (result.token) setToken(result.token);
    await load();
  } catch (err) {
    alert(err.message);
  }
}

async function submitAdminAuth(e) {
  e.preventDefault();
  const form = e.currentTarget;

  if (!(form instanceof HTMLFormElement)) {
    alert('Unable to read the admin login form. Please refresh the page.');
    return;
  }

  const x = Object.fromEntries(new FormData(form).entries());

  try {
    const result = await api('/api/login', { method: 'POST', body: x });

    if (!result.token) throw new Error('Login token was not returned.');

    setToken(result.token);
    await load();

    if (!state.user || state.user.role !== 'admin') {
      alert('These credentials do not belong to an administrator.');
      logout();
      return;
    }

    await loadAdmin();
  } catch (err) {
    alert(err.message);
  }
}

async function load() {
  if (!state.token) {
    home();
    return;
  }

  try {
    const result = await api('/api/dashboard');
    state.user = result.user || result.account || null;
    state.data = result;
    renderClient();
  } catch (err) {
    console.error(err);
    setToken('');
    state.user = null;
    state.data = null;
    alert('Your session has expired. Please login again.');
    home();
  }
}

function renderClient() {
  if (!state.user) {
    home();
    return;
  }

  if (state.user.role === 'admin') {
    loadAdmin();
    return;
  }

  app.innerHTML = `
    ${nav()}
    <main class="page">
      <div class="dashboard-header">
        <div>
          <h1>Welcome, ${esc(state.user.name || state.user.email || 'Client')}</h1>
          <p class="muted">Your Vertex Advisory dashboard</p>
        </div>
      </div>

      <div class="tabs">
        <button onclick="clientTab('overview')">Overview</button>
        <button onclick="clientTab('research')">Research</button>
        <button onclick="clientTab('calls')">Calls</button>
        <button onclick="clientTab('recommendations')">Recommendations</button>
        <button onclick="clientTab('portfolio')">Portfolio</button>
        <button onclick="clientTab('payments')">Payments</button>
        <button onclick="clientTab('notifications')">Notifications</button>
        <button onclick="clientTab('kyc')">KYC</button>
      </div>

      <section id="client-content"></section>
    </main>
  `;

  clientTab('overview');
}

function clientTab(tab) {
  const box = document.getElementById('client-content');
  if (!box) return;

  const d = state.data || {};

  if (tab === 'overview') {
    box.innerHTML = `
      <div class="grid">
        <div class="card">
          <h3>Account</h3>
          <p><strong>Name:</strong> ${esc(state.user.name || '-')}</p>
          <p><strong>Email:</strong> ${esc(state.user.email || '-')}</p>
          <p><strong>Status:</strong> ${esc(state.user.status || 'Active')}</p>
        </div>
        <div class="card">
          <h3>Current Plan</h3>
          <p>${d.plan ? esc(d.plan.name || d.plan.title || 'Active Plan') : 'No active plan'}</p>
        </div>
        <div class="card">
          <h3>Recommendations</h3>
          <p>${Array.isArray(d.recommendations) ? d.recommendations.length : 0} available</p>
        </div>
        <div class="card">
          <h3>Portfolio</h3>
          <p>${Array.isArray(d.portfolio) ? d.portfolio.length : 0} holdings</p>
        </div>
      </div>
    `;
    return;
  }

  if (tab === 'research') {
    const rows = Array.isArray(d.research) ? d.research : [];
    box.innerHTML = `
      <div class="card">
        <h2>Research Reports</h2>
        ${rows.length ? rows.map(r => `
          <div class="list-item">
            <h3>${esc(r.title || r.symbol || 'Research')}</h3>
            <p>${esc(r.summary || r.description || '')}</p>
            <small>${esc(r.date || r.createdAt || '')}</small>
          </div>
        `).join('') : '<p>No research reports available.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'calls') {
    const rows = Array.isArray(d.calls) ? d.calls : [];
    box.innerHTML = `
      <div class="card">
        <h2>Advisory Calls</h2>
        ${rows.length ? rows.map(r => `
          <div class="list-item">
            <h3>${esc(r.symbol || r.title || 'Market Call')}</h3>
            <p>${esc(r.action || r.call || '')}</p>
            <p>${esc(r.entry || '')}${r.target ? ` → ${esc(r.target)}` : ''}${r.stopLoss ? ` | SL: ${esc(r.stopLoss)}` : ''}</p>
          </div>
        `).join('') : '<p>No calls available.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'recommendations') {
    const rows = Array.isArray(d.recommendations) ? d.recommendations : [];
    box.innerHTML = `
      <div class="card">
        <h2>Recommendations</h2>
        ${rows.length ? rows.map(r => `
          <div class="list-item">
            <h3>${esc(r.symbol || r.name || 'Stock')}</h3>
            <p><strong>Action:</strong> ${esc(r.action || r.signal || '-')}</p>
            <p>Target: ${esc(r.target || '-')}</p>
            <p>Stop Loss: ${esc(r.stopLoss || '-')}</p>
            <p>${esc(r.notes || r.reason || '')}</p>
          </div>
        `).join('') : '<p>No recommendations available.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'portfolio') {
    const rows = Array.isArray(d.portfolio) ? d.portfolio : [];
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>My Portfolio</h2>
          <button class="primary" onclick="addHolding()">Add Holding</button>
        </div>
        ${rows.length ? `
          <div class="table-wrap">
            <table>
              <thead><tr><th>Symbol</th><th>Quantity</th><th>Buy Price</th><th>Current Price</th></tr></thead>
              <tbody>${rows.map(r => `
                <tr>
                  <td>${esc(r.symbol || '-')}</td>
                  <td>${esc(r.quantity || 0)}</td>
                  <td>${esc(r.buyPrice || 0)}</td>
                  <td>${esc(r.currentPrice || 0)}</td>
                </tr>
              `).join('')}</tbody>
            </table>
          </div>
        ` : '<p>No holdings added yet.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'payments') {
    const rows = Array.isArray(d.payments) ? d.payments : [];
    const plans = Array.isArray(d.plans) ? d.plans : [];
    box.innerHTML = `
      <div class="card">
        <h2>Bank Transfer / UPI Payment</h2>
        <p class="muted">Transfer the exact plan amount to the account below, then submit your UTR/transaction reference. Your subscription stays pending until an administrator verifies the payment.</p>
        <div id="bank-details"><p>Loading payment details...</p></div>
        <hr>
        <h3>Submit Payment</h3>
        <form id="bank-payment-form">
          <label>Plan</label>
          <select name="planId" required>
            ${plans.map(p => `<option value="${esc(p.id)}">${esc(p.name)} — ₹${esc(p.price)}</option>`).join('')}
          </select>
          <label>UTR / Transaction Reference</label>
          <input name="utr" required minlength="6" maxlength="50" placeholder="Enter UTR / transaction reference" />
          <button class="primary" type="submit">Submit Payment</button>
        </form>
      </div>
      <div class="card">
        <h2>Payment History</h2>
        ${rows.length ? `
          <div class="table-wrap">
            <table>
              <thead><tr><th>Date</th><th>Amount</th><th>Status</th><th>Method</th><th>UTR</th></tr></thead>
              <tbody>${rows.map(r => `
                <tr>
                  <td>${esc(r.createdAt || '-')}</td>
                  <td>₹${esc(r.amount || '-')}</td>
                  <td>${esc(r.status || '-')}</td>
                  <td>${esc(r.method || '-')}</td>
                  <td>${esc((r.details && r.details.utr) || r.reference || '-')}</td>
                </tr>
              `).join('')}</tbody>
            </table>
          </div>
        ` : '<p>No payment records available.</p>'}
      </div>
    `;
    loadBankPaymentInfo();
    const form = document.getElementById('bank-payment-form');
    if (form) form.addEventListener('submit', submitBankPayment);
    return;
  }

  async function loadBankPaymentInfo() {
    try {
      const info = await api('/api/payment-info');
      const el = document.getElementById('bank-details');
      if (!el) return;
      el.innerHTML = `
        <p><strong>Account Name:</strong> ${esc(info.accountName || 'Not configured')}</p>
        <p><strong>Bank:</strong> ${esc(info.bankName || 'Not configured')}</p>
        <p><strong>Account Number:</strong> ${esc(info.accountNumber || 'Not configured')}</p>
        <p><strong>IFSC:</strong> ${esc(info.ifsc || 'Not configured')}</p>
        <p><strong>UPI ID:</strong> ${esc(info.upiId || 'Not configured')}</p>
      `;
    } catch (err) {
      const el = document.getElementById('bank-details');
      if (el) el.innerHTML = `<p class="muted">Payment details are not configured yet.</p>`;
    }
  }

  async function submitBankPayment(e) {
    e.preventDefault();
    const form = e.currentTarget;
    const x = Object.fromEntries(new FormData(form).entries());
    try {
      await api('/api/bank-payment', { method: 'POST', body: x });
      alert('Payment submitted. It will remain pending until the administrator verifies the transfer.');
      await load();
      clientTab('payments');
    } catch (err) {
      alert(err.message);
    }
  }

  if (tab === 'notifications') {
    const rows = Array.isArray(d.notifications) ? d.notifications : [];
    box.innerHTML = `
      <div class="card">
        <h2>Notifications</h2>
        ${rows.length ? rows.map(n => `
          <div class="list-item">
            <h3>${esc(n.title || 'Notification')}</h3>
            <p>${esc(n.message || n.body || '')}</p>
            <small>${esc(n.date || n.createdAt || '')}</small>
          </div>
        `).join('') : '<p>No notifications.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'kyc') {
    const k = d.kyc || state.user.kyc || {};
    box.innerHTML = `
      <div class="card">
        <h2>KYC Status</h2>
        <p><strong>Status:</strong> ${esc(k.status || 'Not submitted')}</p>
        ${k.message ? `<p>${esc(k.message)}</p>` : ''}
        <button class="primary" onclick="submitKyc()">Submit / Update KYC</button>
      </div>
    `;
  }
}

async function addHolding() {
  const symbol = prompt('Enter stock symbol:');
  if (!symbol) return;

  const quantity = prompt('Enter quantity:');
  if (!quantity) return;

  const buyPrice = prompt('Enter buy price:');
  if (!buyPrice) return;

  try {
    await api('/api/portfolio', {
      method: 'POST',
      body: {
        symbol: symbol.toUpperCase(),
        quantity: Number(quantity),
        buyPrice: Number(buyPrice)
      }
    });

    await load();
    alert('Holding added successfully.');
    clientTab('portfolio');
  } catch (err) {
    alert(err.message);
  }
}

async function submitKyc() {
  const pan = prompt('Enter PAN number:');
  if (!pan) return;

  const dob = prompt('Enter date of birth (DD/MM/YYYY):');
  if (!dob) return;

  try {
    await api('/api/kyc', {
      method: 'POST',
      body: { pan, dob }
    });

    await load();
    alert('KYC submitted successfully.');
    clientTab('kyc');
  } catch (err) {
    alert(err.message);
  }
}

async function loadAdmin() {
  try {
    const result = await api('/api/admin');
    renderAdmin(result);
  } catch (err) {
    console.error(err);
    alert(err.message || 'Unable to load the admin dashboard.');
    logout();
  }
}

function renderAdmin(data) {
  const users = Array.isArray(data.users) ? data.users : [];
  const research = Array.isArray(data.research) ? data.research : [];
  const recommendations = Array.isArray(data.recommendations) ? data.recommendations : [];
  const calls = Array.isArray(data.calls) ? data.calls : [];

  app.innerHTML = `
    ${nav()}
    <main class="page">
      <div class="dashboard-header">
        <div>
          <h1>Admin Dashboard</h1>
          <p class="muted">Vertex Advisory administration</p>
        </div>
        <span class="admin-badge">ADMIN</span>
      </div>

      <div class="admin-stats">
        <div class="card"><h3>Users</h3><strong>${users.length}</strong></div>
        <div class="card"><h3>Research</h3><strong>${research.length}</strong></div>
        <div class="card"><h3>Recommendations</h3><strong>${recommendations.length}</strong></div>
        <div class="card"><h3>Calls</h3><strong>${calls.length}</strong></div>
      </div>

      <div class="tabs">
        <button onclick="adminTab('users')">Users</button>
        <button onclick="adminTab('research')">Research</button>
        <button onclick="adminTab('recommendations')">Recommendations</button>
        <button onclick="adminTab('calls')">Calls</button>
        <button onclick="adminTab('payments')">Payments</button>
        <button onclick="adminTab('kyc')">KYC</button>
        <button onclick="adminTab('notifications')">Notifications</button>
        <button onclick="adminTab('plans')">Plans</button>
      </div>

      <section id="admin-content"></section>
    </main>
  `;

  state.adminData = data;
  adminTab('users');
}

function adminTab(tab) {
  const box = document.getElementById('admin-content');
  if (!box) return;

  const d = state.adminData || {};

  if (tab === 'users') {
    const rows = Array.isArray(d.users) ? d.users : [];
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <div><h2>Users</h2><p class="muted">Manage client accounts, status and subscriptions.</p></div>
          <input id="admin-user-search" placeholder="Search name or email" oninput="filterAdminUsers()" />
        </div>
        ${rows.length ? `
          <div class="table-wrap">
            <table id="admin-users-table">
              <thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Plan</th><th>Actions</th></tr></thead>
              <tbody>${rows.map(u => `
                <tr data-user-search="${esc((u.name||'')+' '+(u.email||''))}">
                  <td>${esc(u.name || '-')}</td>
                  <td>${esc(u.email || '-')}</td>
                  <td>${esc(u.role || 'client')}</td>
                  <td>${u.active === false ? '<span class="status-badge">Inactive</span>' : '<span class="status-badge">Active</span>'}</td>
                  <td><select onchange="adminUserPlan(${Number(u.id)}, this.value)">
                    <option value="" ${!u.planId?'selected':''}>No plan</option>
                    ${(d.plans||[]).map(p => `<option value="${Number(p.id)}" ${Number(u.planId)===Number(p.id)?'selected':''}>${esc(p.name)} — ₹${Number(p.price).toLocaleString('en-IN')}</option>`).join('')}
                  </select></td>
                  <td>${u.role==='admin' ? '<span class="muted">Protected</span>' : `<button class="secondary" onclick="adminUserStatus(${Number(u.id)}, ${u.active === false ? 'true':'false'})">${u.active === false ? 'Activate':'Deactivate'}</button>`}</td>
                </tr>
              `).join('')}</tbody>
            </table>
          </div>
        ` : '<p>No users found.</p>'}
      </div>
    `;
    return;
    `;
    return;
  }

  if (tab === 'research') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Research Reports</h2>
          <button class="primary" onclick="adminPost('research')">Add Research</button>
        </div>
        ${renderAdminList(d.research, 'research')}
      </div>
    `;
    return;
  }

  if (tab === 'recommendations') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Recommendations</h2>
          <button class="primary" onclick="adminPost('recommendations')">Add Recommendation</button>
        </div>
        ${renderAdminList(d.recommendations, 'recommendations')}
      </div>
    `;
    return;
  }

  if (tab === 'calls') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Advisory Calls</h2>
          <button class="primary" onclick="adminPost('calls')">Add Call</button>
        </div>
        ${renderAdminList(d.calls, 'calls')}
      </div>
    `;
    return;
  }

  if (tab === 'payments') {
    const rows = Array.isArray(d.payments) ? d.payments : [];
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Payments</h2>
        </div>
        ${rows.length ? `
          <div class="table-wrap">
            <table>
              <thead>
                <tr><th>ID</th><th>User</th><th>Plan</th><th>Amount</th><th>Method</th><th>UTR</th><th>Status</th><th>Action</th></tr>
              </thead>
              <tbody>
                ${rows.map(p => {
                  const utr = p.details && p.details.utr ? p.details.utr : '-';
                  return `<tr>
                    <td>${esc(p.id)}</td>
                    <td>${esc(p.userId || '-')}</td>
                    <td>${esc(p.planId || '-')}</td>
                    <td>₹${esc(p.amount || 0)}</td>
                    <td>${esc(p.method || '-')}</td>
                    <td>${esc(utr)}</td>
                    <td>${esc(p.status || 'pending')}</td>
                    <td>
                      <select onchange="adminPaymentStatus(${Number(p.id)}, this.value)">
                        <option value="pending" ${p.status==='pending'?'selected':''}>Pending</option>
                        <option value="paid" ${p.status==='paid'?'selected':''}>Paid</option>
                        <option value="rejected" ${p.status==='rejected'?'selected':''}>Rejected</option>
                      </select>
                    </td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
          <p class="muted">Changing a payment to <strong>Paid</strong> activates that payment's plan for the client.</p>
        ` : '<p>No payments found.</p>'}
      </div>
    `;
    return;
  }

  if (tab === 'kyc') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>KYC Applications</h2>
          <button class="primary" onclick="adminPost('kyc')">Update KYC</button>
        </div>
        ${renderAdminList(d.kyc, 'kyc')}
      </div>
    `;
    return;
  }

  if (tab === 'notifications') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Notifications</h2>
          <button class="primary" onclick="adminPost('notifications')">Send Notification</button>
        </div>
        ${renderAdminList(d.notifications, 'notifications')}
      </div>
    `;
    return;
  }

  if (tab === 'plans') {
    box.innerHTML = `
      <div class="card">
        <div class="section-header">
          <h2>Plans</h2>
          <button class="primary" onclick="adminPost('plans')">Add Plan</button>
        </div>
        ${renderAdminList(d.plans, 'plans')}
      </div>
    `;
  }
}

function renderAdminList(items, type) {
  const rows = Array.isArray(items) ? items : [];

  if (!rows.length) return `<p>No ${esc(type)} found.</p>`;

  return rows.map(item => {
    const title = item.title || item.name || item.symbol || item.email || item.id || 'Item';
    const description = item.summary || item.description || item.message || item.action || item.status || '';

    return `
      <div class="list-item">
        <h3>${esc(title)}</h3>
        <p>${esc(description)}</p>
        ${item.date || item.createdAt ? `<small>${esc(item.date || item.createdAt)}</small>` : ''}
      </div>
    `;
  }).join('');
}

function filterAdminUsers(){
  const q=String(document.getElementById('admin-user-search')?.value||'').toLowerCase().trim();
  document.querySelectorAll('#admin-users-table tbody tr').forEach(row=>{row.style.display=String(row.dataset.userSearch||'').toLowerCase().includes(q)?'':'none';});
}

async function adminUserStatus(id, active){
  try{
    await api('/api/admin/user',{method:'POST',body:JSON.stringify({id,active})});
    await loadAdmin();
    alert(active?'Client account activated.':'Client account deactivated.');
  }catch(err){alert(err.message||'Unable to update account status.');}
}

async function adminUserPlan(id, planId){
  try{
    await api('/api/admin/user',{method:'POST',body:JSON.stringify({id,planId:planId||null})});
    await loadAdmin();
    alert('Client plan updated.');
  }catch(err){alert(err.message||'Unable to update client plan.');}
}

async function adminPaymentStatus(id, status) {
  if (!id || !status) return;
  try {
    await api('/api/admin/payment', {
      method: 'POST',
      body: { id: Number(id), status }
    });
    alert(`Payment #${id} updated to ${status}.`);
    await loadAdmin();
  } catch (err) {
    alert(err.message || 'Unable to update payment.');
    await loadAdmin();
  }
}

async function adminPost(type) {
  let payload = {};

  if (type === 'research') {
    payload.title = prompt('Research title:');
    if (!payload.title) return;
    payload.symbol = prompt('Stock symbol:') || '';
    payload.summary = prompt('Research summary:') || '';
  } else if (type === 'recommendations') {
    payload.symbol = prompt('Stock symbol:');
    if (!payload.symbol) return;
    payload.action = prompt('Action (BUY/SELL/HOLD):') || '';
    payload.target = prompt('Target price:') || '';
    payload.stopLoss = prompt('Stop loss:') || '';
    payload.notes = prompt('Notes:') || '';
  } else if (type === 'calls') {
    payload.symbol = prompt('Stock symbol:');
    if (!payload.symbol) return;
    payload.action = prompt('Call/action:') || '';
    payload.entry = prompt('Entry price:') || '';
    payload.target = prompt('Target price:') || '';
    payload.stopLoss = prompt('Stop loss:') || '';
  } else if (type === 'kyc') {
    payload.userId = prompt('User ID:');
    if (!payload.userId) return;
    payload.status = prompt('KYC status (approved/rejected/pending):');
    if (!payload.status) return;
  } else if (type === 'notifications') {
    payload.title = prompt('Notification title:');
    if (!payload.title) return;
    payload.message = prompt('Notification message:');
    if (!payload.message) return;
  } else if (type === 'plans') {
    payload.name = prompt('Plan name:');
    if (!payload.name) return;
    payload.price = prompt('Plan price:') || '';
    payload.description = prompt('Plan description:') || '';
  } else {
    alert('This admin action is not configured yet.');
    return;
  }

  try {
    await api(`/api/admin/${type}`, {
      method: 'POST',
      body: payload
    });

    alert(type.charAt(0).toUpperCase() + type.slice(1) + ' saved successfully.');
    await loadAdmin();
  } catch (err) {
    alert(err.message);
  }
}

load();
