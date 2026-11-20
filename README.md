# QELIVARO Render backend

This private repository contains the Node.js authentication provisioning API for QELIVARO.

## Render settings
- Runtime: Node
- Build command: npm install
- Start command: npm start
- Health check path: /health

## Required server environment variables
- SUPABASE_URL
- SUPABASE_SERVICE_ROLE_KEY
- CLERK_SECRET_KEY
- CLERK_ISSUER (optional; defaults to the QELIVARO Clerk issuer)

Never place secret values in this repository or in frontend code.
