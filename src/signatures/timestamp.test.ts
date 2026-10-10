/**
 * Tests for HttpTimestampAuthority network handling.
 *
 * Token parsing is covered end to end by the timestamping integration tests;
 * these cover the request itself: the timeout must hold through the body
 * read and the body must be size-capped.
 */

import { describe, expect, it } from "vitest";

import { HttpTimestampAuthority } from "./timestamp";
import { TimestampError } from "./types";

const digest = new Uint8Array(32);

describe("HttpTimestampAuthority", () => {
  it("uses the custom fetch with the timestamp request", async () => {
    const calls: { url: string; init?: RequestInit }[] = [];

    const fetchFn = (async (url: string, init?: RequestInit) => {
      calls.push({ url, init });

      return new Response(null, { status: 500, statusText: "Server Error" });
    }) as unknown as typeof globalThis.fetch;

    const tsa = new HttpTimestampAuthority("https://tsa.example/tsr", { fetch: fetchFn });

    await expect(tsa.timestamp(digest, "SHA-256")).rejects.toThrow(
      "TSA request failed: HTTP 500 Server Error",
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("https://tsa.example/tsr");
    expect(calls[0].init?.method).toBe("POST");
  });

  it("rejects within the timeout when the response body stalls after headers", async () => {
    const stallingFetch = (async () =>
      new Response(
        new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array([0x30]));
          },
        }),
        { status: 200 },
      )) as unknown as typeof globalThis.fetch;

    const tsa = new HttpTimestampAuthority("https://tsa.example/tsr", {
      fetch: stallingFetch,
      timeout: 100,
    });
    const started = Date.now();

    const error = await tsa.timestamp(digest, "SHA-256").catch((e: unknown) => e);

    expect(error).toBeInstanceOf(TimestampError);
    expect((error as TimestampError).message).toBe("TSA request timed out after 100ms");
    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("rejects a response body larger than 1 MB", async () => {
    const oversizedFetch = (async () =>
      new Response(new Uint8Array(1024 * 1024 + 1), {
        status: 200,
      })) as unknown as typeof globalThis.fetch;

    const tsa = new HttpTimestampAuthority("https://tsa.example/tsr", { fetch: oversizedFetch });

    await expect(tsa.timestamp(digest, "SHA-256")).rejects.toThrow(
      "TSA request failed: Response body exceeds 1048576 bytes",
    );
  });
});
