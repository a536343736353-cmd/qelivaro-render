import { createServer } from "node:http";
import { createClient } from "@supabase/supabase-js";
import { createRemoteJWKSet, jwtVerify } from "jose";

const PORT = Number(process.env.PORT || 10000);
const CLERK_ISSUER = process.env.CLERK_ISSUER || "https://ethical-bird-3686.clerk.accounts.dev";
const ALLOWED_ORIGINS = new Set([
  "https://qelivaro.a23224259.workers.dev",
  "https://qelivaro-preview.a23224259.workers.dev",
  "http://localhost:5173",
]);
const jwks = createRemoteJWKSet(new URL(`${CLERK_ISSUER}/.well-known/jwks.json`));

function send(res, status, body, origin) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Origin": origin && ALLOWED_ORIGINS.has(origin)
      ? origin : "https://qelivaro.a23224259.workers.dev",
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Vary": "Origin",
  });
  res.end(JSON.stringify(body));
}

async function readBody(req) {
  let raw = "";
  for await (const chunk of req) {
    raw += chunk;
    if (raw.length > 16_384) throw new Error("Request too large");
  }
  return raw ? JSON.parse(raw) : {};
}

async function provision(req, res, origin) {
  if (!origin || !ALLOWED_ORIGINS.has(origin)) {
    return send(res, 403, { error: "Origin not allowed." }, origin);
  }
  const supabaseUrl = process.env.SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;
  const clerkSecretKey = process.env.CLERK_SECRET_KEY;
  if (!supabaseUrl || !serviceRoleKey || !clerkSecretKey) {
    return send(res, 503, { error: "Render account setup is not configured yet. The administrator must add the required server environment variables." }, origin);
  }

  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!token) return send(res, 401, { error: "Sign in to Google before continuing." }, origin);

  let clerkUserId;
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: CLERK_ISSUER,
      algorithms: ["RS256"],
    });
    const authorizedParty = typeof payload.azp === "string" ? payload.azp : "";
    if (!payload.sub || (authorizedParty && authorizedParty !== origin)) {
      return send(res, 401, { error: "Your QELIVARO session is not valid for this application." }, origin);
    }
    clerkUserId = payload.sub;
  } catch {
    return send(res, 401, { error: "Your Clerk session is invalid or expired." }, origin);
  }

  let clerkUser;
  try {
    const response = await fetch(`https://api.clerk.com/v1/users/${encodeURIComponent(clerkUserId)}`, {
      headers: { Authorization: `Bearer ${clerkSecretKey}` },
    });
    if (!response.ok) throw new Error("Clerk lookup failed");
    clerkUser = await response.json();
    if (clerkUser.id !== clerkUserId) throw new Error("Clerk subject mismatch");
  } catch {
    return send(res, 503, { error: "QELIVARO could not verify your Clerk account. Please try again." }, origin);
  }

  const primaryEmail = clerkUser.email_addresses?.find(item => item.id === clerkUser.primary_email_address_id);
  const verifiedEmail = primaryEmail?.verification?.status === "verified" ? primaryEmail.email_address : null;
  const primaryPhone = clerkUser.phone_numbers?.find(item => item.id === clerkUser.primary_phone_number_id);
  const verifiedPhone = primaryPhone?.verification?.status === "verified" ? primaryPhone.phone_number : null;
  if (!verifiedEmail && !verifiedPhone) {
    return send(res, 403, { error: "Verify your email address or phone number in Clerk before finishing QELIVARO signup." }, origin);
  }

  const admin = createClient(supabaseUrl, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: existingLink, error: lookupError } = await admin
    .from("clerk_identity_links")
    .select("clerk_user_id,supabase_user_id")
    .eq("clerk_user_id", clerkUserId)
    .maybeSingle();
  if (lookupError) {
    return send(res, 503, { error: "The QELIVARO identity database is not ready. Finish the identity-link database setup first." }, origin);
  }
  if (existingLink?.supabase_user_id) {
    return send(res, 200, { provisioned: true, alreadyProvisioned: true }, origin);
  }

  const displayName = [clerkUser.first_name, clerkUser.last_name].filter(Boolean).join(" ").trim() || clerkUser.username || "";
  const attributes = {
    ...(verifiedEmail ? { email: verifiedEmail, email_confirm: true } : { phone: verifiedPhone, phone_confirm: true }),
    user_metadata: {
      display_name: displayName,
      auth_provider: "clerk",
      ...(verifiedPhone ? { phone_number: verifiedPhone } : {}),
    },
    app_metadata: { provider: "clerk" },
  };
  const { data: created, error: createError } = await admin.auth.admin.createUser(attributes);
  if (createError || !created.user) {
    return send(res, 409, { error: "This verified email or phone may already belong to a QELIVARO account. Sign in to that account first, then connect Clerk from Account." }, origin);
  }
  const { error: insertError } = await admin.from("clerk_identity_links").insert({
    clerk_user_id: clerkUserId,
    supabase_user_id: created.user.id,
  });
  if (insertError) {
    await admin.auth.admin.deleteUser(created.user.id);
    return send(res, 503, { error: "QELIVARO could not finish creating the account link. Please try again." }, origin);
  }
  return send(res, 200, { provisioned: true, alreadyProvisioned: false }, origin);
}

const server = createServer(async (req, res) => {
  const origin = req.headers.origin || null;
  if (req.method === "OPTIONS") return send(res, 204, {}, origin);
  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true, service: "qelivaro-auth" }, origin);
  if (req.method === "POST" && req.url === "/api/auth/provision") {
    try { await readBody(req); return await provision(req, res, origin); }
    catch { return send(res, 400, { error: "Invalid request." }, origin); }
  }
  return send(res, 404, { error: "Not found." }, origin);
});
server.listen(PORT, "0.0.0.0", () => console.log(`QELIVARO auth listening on ${PORT}`));
