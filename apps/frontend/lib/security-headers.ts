/**
 * The application-wide Content-Security-Policy for the Next.js pages.
 *
 * The policy is generated per request because script-src carries a nonce.
 * Outbound MCP OAuth discovery is browser-driven, so connect-src may be
 * extended with a narrow operator-controlled list of exact HTTPS origins.
 */

import { getOAuthConnectSources } from "./oauth-connect-src";

export const NONCE_HEADER = "x-nonce";

export interface ContentSecurityPolicyOptions {
  /** Extra form-action sources used only by the OAuth consent document. */
  formActionSources?: readonly string[];
}

export function buildContentSecurityPolicy(
  nonce: string,
  options: ContentSecurityPolicyOptions = {},
): string {
  const devEval = process.env.NODE_ENV === "production" ? "" : " 'unsafe-eval'";
  const formAction = ["'self'", ...(options.formActionSources ?? [])].join(" ");
  const oauthConnectSources = getOAuthConnectSources();

  if (oauthConnectSources.rejected.length > 0) {
    console.warn(
      "[security] Ignoring invalid OAUTH_CONNECT_SRC_ORIGINS entries:",
      oauthConnectSources.rejected,
    );
  }

  const connectSources = ["'self'", ...oauthConnectSources.sources].join(" ");

  return [
    "default-src 'self'",
    "base-uri 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "frame-src 'none'",
    `form-action ${formAction}`,
    `script-src 'self' 'nonce-${nonce}'${devEval}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    `connect-src ${connectSources}`,
  ].join("; ");
}
