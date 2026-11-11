import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-device-key",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

async function sha256(value: string): Promise<string> {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!url || !serviceKey) return json({ error: "server_not_configured" }, 503);

  const db = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  let body: Record<string, unknown>;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid_json" }, 400);
  }

  const action = String(body.action ?? "");

  // Pairing code is single-use and expires. The app-generated device secret is
  // hashed here; its raw value is never stored in the database.
  if (action === "enroll") {
    const pairingCode = String(body.pairing_code ?? "");
    const deviceSecret = String(body.device_secret ?? "");
    const label = String(body.device_label ?? "Android vault").slice(0, 80);
    if (pairingCode.length < 24 || deviceSecret.length < 32) {
      return json({ error: "invalid_enrollment_input" }, 400);
    }

    const { data: deviceId, error: enrollError } = await db.rpc("enroll_vault_device", {
      p_code_hash: await sha256(pairingCode),
      p_device_key_hash: await sha256(deviceSecret),
      p_label: label,
    });
    if (enrollError || !deviceId) return json({ error: "pairing_code_invalid_expired_or_used" }, 401);

    return json({ device_id: deviceId });
  }

  const deviceSecret = req.headers.get("x-device-key") ?? "";
  if (deviceSecret.length < 32) return json({ error: "device_auth_required" }, 401);

  const { data: device, error: deviceError } = await db
    .from("vault_devices")
    .select("id")
    .eq("device_key_hash", await sha256(deviceSecret))
    .is("disabled_at", null)
    .maybeSingle();

  if (deviceError || !device) return json({ error: "device_auth_failed" }, 401);

  await db.from("vault_devices").update({ last_seen_at: new Date().toISOString() }).eq("id", device.id);

  if (action === "poll") {
    const { data, error } = await db
      .from("vault_commands")
      .select("id, action, path, args, status, requested_at, expires_at")
      .eq("device_id", device.id)
      .in("status", ["pending", "approved"])
      .gt("expires_at", new Date().toISOString())
      .order("requested_at", { ascending: true })
      .limit(20);
    if (error) return json({ error: "command_poll_failed" }, 500);
    return json({ commands: data ?? [] });
  }

  const commandId = String(body.command_id ?? "");
  if (!/^[0-9a-f-]{36}$/i.test(commandId)) return json({ error: "invalid_command_id" }, 400);

  if (action === "approve" || action === "reject") {
    const status = action === "approve" ? "approved" : "rejected";
    const patch = status === "approved"
      ? { status, approved_at: new Date().toISOString() }
      : { status };
    const { data, error } = await db
      .from("vault_commands")
      .update(patch)
      .eq("id", commandId)
      .eq("device_id", device.id)
      .eq("status", "pending")
      .gt("expires_at", new Date().toISOString())
      .select("id")
      .maybeSingle();
    if (error || !data) return json({ error: "command_not_pending_or_expired" }, 409);
    return json({ ok: true, status });
  }

  if (action === "complete" || action === "fail") {
    const patch = action === "complete"
      ? { status: "completed", completed_at: new Date().toISOString(), result: body.result ?? {} }
      : {
          status: "failed",
          completed_at: new Date().toISOString(),
          error_message: String(body.error ?? "device_operation_failed").slice(0, 500),
        };
    const { data, error } = await db
      .from("vault_commands")
      .update(patch)
      .eq("id", commandId)
      .eq("device_id", device.id)
      .eq("status", "approved")
      .select("id")
      .maybeSingle();
    if (error || !data) return json({ error: "command_not_approved_or_already_finished" }, 409);
    return json({ ok: true });
  }

  return json({ error: "unsupported_action" }, 400);
});
