/**
 * Security invariants for the per-request document CSP.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

import { buildContentSecurityPolicy, NONCE_HEADER } from "./security-headers";

function cspForEnv(env: string): string {
  vi.stubEnv("NODE_ENV", env);
  try {
    return buildContentSecurityPolicy("TESTNONCE==");
  } finally {
    vi.unstubAllEnvs();
  }
}

function directive(csp: string, name: string): string | undefined {
  return csp
    .split(";")
    .map((d) => d.trim())
    .find((d) => d.startsWith(name));
}

afterEach(() => {
  vi.unstubAllEnvs();
});

describe("buildContentSecurityPolicy (production)", () => {
  const csp = cspForEnv("production");

  it("carries the nonce in script-src and nothing looser", () => {
    expect(csp).toContain("script-src 'self' 'nonce-TESTNONCE=='");
  });

  it("never allows unsafe-inline or unsafe-eval for scripts", () => {
    const scriptSrc = directive(csp, "script-src");
    expect(scriptSrc).toBeDefined();
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(scriptSrc).not.toContain("unsafe-eval");
  });

  it("keeps default-src, object-src and base-uri locked down", () => {
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'self'");
  });

  it("denies framing in both directions and pins form-action", () => {
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("frame-src 'none'");
    expect(csp).toContain("form-action 'self'");
  });

  it("keeps connect-src same-origin when the allowlist is unset", () => {
    expect(directive(csp, "connect-src")).toBe("connect-src 'self'");
  });

  it("adds only canonical configured OAuth origins to connect-src", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv(
      "OAUTH_CONNECT_SRC_ORIGINS",
      "https://mcp.vercel.com https://VERCEL.com:443",
    );
    const widened = buildContentSecurityPolicy("TESTNONCE==");
    expect(directive(widened, "connect-src")).toBe(
      "connect-src 'self' https://mcp.vercel.com https://vercel.com",
    );
  });

  it("does not include invalid configured OAuth sources", () => {
    vi.stubEnv("NODE_ENV", "production");
    vi.stubEnv(
      "OAUTH_CONNECT_SRC_ORIGINS",
      "javascript:alert(1) http://vercel.com",
    );
    const widened = buildContentSecurityPolicy("TESTNONCE==");
    expect(directive(widened, "connect-src")).toBe("connect-src 'self'");
  });

  it("pins form-action to exactly 'self' when no extra source is given", () => {
    expect(directive(csp, "form-action")).toBe("form-action 'self'");
  });

  it("widens form-action to the given sources and touches nothing else", () => {
    vi.stubEnv("NODE_ENV", "production");
    const widened = buildContentSecurityPolicy("TESTNONCE==", {
      formActionSources: ["https://claude.ai"],
    });
    expect(directive(widened, "form-action")).toBe(
      "form-action 'self' https://claude.ai",
    );
    const strip = (v: string) => v.replace(/form-action[^;]*/, "form-action X");
    expect(strip(widened)).toBe(strip(csp));
  });

  it("allows unsafe-inline for styles only, not scripts", () => {
    const styleSrc = directive(csp, "style-src");
    expect(styleSrc).toContain("'unsafe-inline'");
    expect(styleSrc).not.toContain("nonce-");
  });

  it("exposes the nonce request-header name", () => {
    expect(NONCE_HEADER).toBe("x-nonce");
  });
});

describe("buildContentSecurityPolicy (development)", () => {
  const csp = cspForEnv("development");

  it("adds unsafe-eval for next dev, but never unsafe-inline", () => {
    const scriptSrc = directive(csp, "script-src");
    expect(scriptSrc).toContain("'unsafe-eval'");
    expect(scriptSrc).not.toContain("unsafe-inline");
    expect(scriptSrc).toContain("'nonce-TESTNONCE=='");
  });
});
