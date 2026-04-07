/**
 * Hive PostHog analytics.
 * Tracks anonymous tool usage server-side — no prompt text, no PII.
 * userId is one-way hashed before sending.
 *
 * Same PostHog project as Socials; events are distinguished by product: "hive".
 */

import { PostHog } from "posthog-node";
import { createHash } from "crypto";

const POSTHOG_HOST = "https://us.i.posthog.com";
const POSTHOG_API_KEY = "phc_HzbU9VFUqbZA66VeBnhpaQtgTkjhw70JekcWxsHVtJM";

const posthog = new PostHog(POSTHOG_API_KEY, {
  host: POSTHOG_HOST,
  flushAt: 1,       // send immediately — serverless invocations are short-lived
  flushInterval: 0,
});

/** One-way hash of userId so PostHog never sees real IDs */
function anonymize(userId: string): string {
  return createHash("sha256").update(`hive:${userId}`).digest("hex").slice(0, 16);
}

interface ToolProperties {
  domain?: string;
  action_key?: string;
  workflow_key?: string;
  query?: string;
  direction?: string;
  result?: string;
  block_count?: number;
  workflow_count?: number;
  action_count?: number;
  step_count?: number;
  duration_ms?: number;
}

/**
 * Track an MCP tool call. Fire-and-forget — never throws.
 */
export function trackTool(
  userId: string,
  tool: string,
  properties: ToolProperties = {},
): void {
  try {
    posthog.capture({
      distinctId: anonymize(userId),
      event: "hive_tool_called",
      properties: {
        product: "hive",
        client: "claude",
        tool,
        os: process.platform,
        ...properties,
      },
    });
    void posthog.flush();
  } catch {
    // never let analytics break the tool
  }
}

/**
 * Track agent registration. Fire-and-forget.
 */
export function trackRegister(userId: string): void {
  try {
    posthog.capture({
      distinctId: anonymize(userId),
      event: "hive_agent_registered",
      properties: { product: "hive", client: "claude" },
    });
    void posthog.flush();
  } catch {}
}

export async function shutdownAnalytics(): Promise<void> {
  await posthog.shutdown();
}
