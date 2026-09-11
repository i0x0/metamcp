import { describe, expect, it } from "vitest";

import { parseOAuthConnectSources } from "./oauth-connect-src";

describe("parseOAuthConnectSources", () => {
  it("accepts exact HTTPS origins", () => {
    expect(
      parseOAuthConnectSources(
        "https://mcp.vercel.com https://vercel.com",
      ),
    ).toEqual({
      sources: ["https://mcp.vercel.com", "https://vercel.com"],
      rejected: [],
    });
  });

  it("accepts commas, canonicalizes, and deduplicates", () => {
    expect(
      parseOAuthConnectSources(
        "https://VERCEL.com, https://vercel.com:443",
      ).sources,
    ).toEqual(["https://vercel.com"]);
  });

  it.each([
    "http://vercel.com",
    "https://trusted.example@evil.example",
    "https://vercel.com/oauth",
    "https://vercel.com?token=secret",
    "https://vercel.com/#fragment",
    "https://*.vercel.com",
    "https://localhost",
    "javascript:alert(1)",
  ])("rejects unsafe source %s", (source) => {
    const result = parseOAuthConnectSources(source);
    expect(result.sources).toEqual([]);
    expect(result.rejected).toEqual([source]);
  });

  it("does not permit raw CSP directive injection", () => {
    const result = parseOAuthConnectSources(
      "https://vercel.com; script-src *",
    );
    expect(result.sources).toEqual([]);
    expect(result.rejected.length).toBeGreaterThan(0);
  });

  it("returns an empty allowlist when unset", () => {
    expect(parseOAuthConnectSources(undefined)).toEqual({
      sources: [],
      rejected: [],
    });
  });
});
