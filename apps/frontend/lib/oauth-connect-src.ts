const ENV_NAME = "OAUTH_CONNECT_SRC_ORIGINS";
const MAX_ORIGINS = 32;

export interface OAuthConnectSourceResult {
  sources: string[];
  rejected: string[];
}

/**
 * Parse the exact HTTPS origins the browser may contact during outbound MCP
 * OAuth. Input may be comma- or whitespace-separated.
 *
 * Values are never inserted into CSP verbatim: every accepted entry is parsed
 * as a URL and reduced to its canonical origin. Paths, queries, fragments,
 * credentials, wildcards, localhost and non-HTTPS schemes are rejected.
 */
export function parseOAuthConnectSources(
  rawValue: string | undefined,
): OAuthConnectSourceResult {
  if (!rawValue?.trim()) {
    return { sources: [], rejected: [] };
  }

  const candidates = rawValue
    .split(/[\s,]+/)
    .map((value) => value.trim())
    .filter(Boolean);

  const sources = new Set<string>();
  const rejected: string[] = [];

  for (const candidate of candidates.slice(0, MAX_ORIGINS)) {
    try {
      const url = new URL(candidate);
      const isExactOrigin =
        url.pathname === "/" && url.search === "" && url.hash === "";
      const isLocalhost =
        url.hostname === "localhost" || url.hostname.endsWith(".localhost");

      if (
        url.protocol !== "https:" ||
        url.username !== "" ||
        url.password !== "" ||
        !isExactOrigin ||
        url.hostname.includes("*") ||
        isLocalhost
      ) {
        rejected.push(candidate);
        continue;
      }

      sources.add(url.origin);
    } catch {
      rejected.push(candidate);
    }
  }

  if (candidates.length > MAX_ORIGINS) {
    rejected.push(...candidates.slice(MAX_ORIGINS));
  }

  return { sources: [...sources], rejected };
}

/** Read at request time so a container restart can change the allowlist. */
export function getOAuthConnectSources(): OAuthConnectSourceResult {
  return parseOAuthConnectSources(process.env[ENV_NAME]);
}
