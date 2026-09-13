# Vertex Advisory — Full Client Portal Demo

## Included modules
- Admin panel
- Client account registration/login
- Subscription plans
- Research publishing
- Advisory call scheduling
- Buy/Sell/Hold recommendations
- Client portfolio tracking
- Payment queue/status
- Notifications
- KYC submission and admin review
- Password hashing with Node `scrypt`
- Signed session tokens using HMAC JWT-style tokens
- File-backed demo database (`data.json`)

## Run
Requires Node.js 18+.

```bash
node server.js
```
Open http://localhost:3000

### Demo admin
Email: `admin@vertexadvisory.in`
Password: `Admin@12345`

Change these credentials and `JWT_SECRET` before any real deployment.

## Production checklist
This is a functional prototype, not a production financial platform. Before taking real clients or money:
1. Replace the JSON database with PostgreSQL/MySQL and add migrations/backups.
2. Use a mature auth/session system, HTTPS, CSRF protection, rate limiting, email verification, MFA and secure cookie sessions.
3. Integrate a compliant payment provider; do not store card details.
4. Integrate an approved KYC provider and encrypted document storage.
5. Add audit logs, RBAC, admin MFA and monitoring.
6. Connect licensed market-data feeds if showing live prices.
7. Implement applicable SEBI/Indian regulatory requirements, disclosures, suitability/risk profiling, record keeping and consent workflows before offering investment-advisory services.
8. Have the legal/compliance architecture reviewed by a qualified professional.
