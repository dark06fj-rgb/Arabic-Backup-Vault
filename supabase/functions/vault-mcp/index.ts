import { createClient } from "npm:@supabase/supabase-js@2";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, content-type, mcp-protocol-version",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

const response = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });

async function authorized(req: Request, expected: string): Promise<boolean> {
  const supplied = req.headers.get("authorization") ?? "";
  if (!supplied.startsWith("Bearer ")) return false;
  const actualHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(supplied.slice(7)));
  const expectedHash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(expected));
  const a = new Uint8Array(actualHash);
  const b = new Uint8Array(expectedHash);
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a[i] ^ b[i];
  return difference === 0;
}

function rpcResult(id: unknown, result: unknown) {
  return { jsonrpc: "2.0", id, result };
}

function rpcError(id: unknown, code: number, message: string) {
  return { jsonrpc: "2.0", id, error: { code, message } };
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return response({ error: "method_not_allowed" }, 405);

  const accessToken = Deno.env.get("VAULT_MCP_ACCESS_TOKEN") ?? "";
  const url = Deno.env.get("SUPABASE_URL");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  if (!accessToken || accessToken.length < 32 || !url || !serviceKey) {
    return response({ error: "mcp_server_not_configured" }, 503);
  }
  if (!(await authorized(req, accessToken))) return response({ error: "unauthorized" }, 401);

  let message: Record<string, unknown>;
  try {
    message = await req.json();
  } catch {
    return response({ error: "invalid_json" }, 400);
  }

  const id = message.id;
  const method = String(message.method ?? "");
  if (method.startsWith("notifications/")) return new Response(null, { status: 202, headers: corsHeaders });
  if (message.jsonrpc !== "2.0" || !method) return response(rpcError(id, -32600, "Invalid JSON-RPC request"));

  if (method === "initialize") {
    return response(rpcResult(id, {
      protocolVersion: "2025-03-26",
      capabilities: { tools: {} },
      serverInfo: { name: "arabic-backup-vault", version: "0.1.0" },
      instructions: "This server sends read-only file-list requests to the user's paired Android vault. Every command remains pending until the user approves it in the Android app. Never claim a command completed until get_command reports completed.",
    }));
  }

  if (method === "ping") return response(rpcResult(id, {}));

  const db = createClient(url, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });

  if (method === "tools/list") {
    return response(rpcResult(id, {
      tools: [
        {
          name: "vault_list_devices",
          description: "List paired, enabled Android vault devices and their last contact time.",
          inputSchema: { type: "object", properties: {}, additionalProperties: false },
        },
        {
          name: "vault_request_file_list",
          description: "Queue a read-only request to list files in the Android vault workspace. The phone user must approve it in the app. This tool only queues the request; use vault_get_command to retrieve the result after approval and execution.",
          inputSchema: {
            type: "object",
            properties: { device_id: { type: "string", description: "ID of the paired Android device." } },
            required: ["device_id"],
            additionalProperties: false,
          },
        },
        {
          name: "vault_get_command",
          description: "Get the status and result of a previously queued Android vault command by command ID.",
          inputSchema: {
            type: "object",
            properties: { command_id: { type: "string", description: "Command ID returned by vault_request_file_list." } },
            required: ["command_id"],
            additionalProperties: false,
          },
        },
      ],
    }));
  }

  if (method !== "tools/call") return response(rpcError(id, -32601, "Method not found"));

  const params = (message.params ?? {}) as Record<string, unknown>;
  const name = String(params.name ?? "");
  const args = (params.arguments ?? {}) as Record<string, unknown>;

  try {
    if (name === "vault_list_devices") {
      const { data, error } = await db.from("vault_devices")
        .select("id,label,last_seen_at,created_at")
        .is("disabled_at", null)
        .order("last_seen_at", { ascending: false, nullsFirst: false })
        .limit(50);
      if (error) throw error;
      return response(rpcResult(id, {
        content: [{ type: "text", text: JSON.stringify(data ?? []) }],
      }));
    }

    if (name === "vault_request_file_list") {
      const deviceId = String(args.device_id ?? "");
      if (!/^[0-9a-f-]{36}$/i.test(deviceId)) {
        return response(rpcResult(id, { isError: true, content: [{ type: "text", text: "Invalid device_id" }] }));
      }
      const { data: device, error: deviceError } = await db.from("vault_devices")
        .select("id,label").eq("id", deviceId).is("disabled_at", null).maybeSingle();
      if (deviceError || !device) {
        return response(rpcResult(id, { isError: true, content: [{ type: "text", text: "Device not found or disabled" }] }));
      }
      const { data: command, error } = await db.from("vault_commands")
        .insert({ device_id: deviceId, action: "list_files", path: "/" })
        .select("id,status,requested_at,expires_at")
        .single();
      if (error) throw error;
      return response(rpcResult(id, {
        content: [{ type: "text", text: JSON.stringify({
          message: "Request queued. The phone user must approve it in the Android app.",
          device: device.label,
          command,
        }) }],
      }));
    }

    if (name === "vault_get_command") {
      const commandId = String(args.command_id ?? "");
      if (!/^[0-9a-f-]{36}$/i.test(commandId)) {
        return response(rpcResult(id, { isError: true, content: [{ type: "text", text: "Invalid command_id" }] }));
      }
      const { data, error } = await db.from("vault_commands")
        .select("id,device_id,action,path,status,requested_at,expires_at,approved_at,completed_at,result,error_message")
        .eq("id", commandId).maybeSingle();
      if (error) throw error;
      if (!data) return response(rpcResult(id, { isError: true, content: [{ type: "text", text: "Command not found" }] }));
      return response(rpcResult(id, {
        content: [{ type: "text", text: JSON.stringify(data) }],
      }));
    }

    return response(rpcResult(id, { isError: true, content: [{ type: "text", text: "Unknown tool" }] }));
  } catch (error) {
    console.error("vault-mcp tool failed", error);
    return response(rpcResult(id, {
      isError: true,
      content: [{ type: "text", text: "Vault database operation failed" }],
    }));
  }
});
