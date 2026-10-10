/**
 * Tests for bounded HTTP fetching.
 *
 * The timeout must cover the whole request including the body read, and the
 * body must be size-capped, so a server that sends headers and then stalls
 * (or streams without end) cannot hang signing or exhaust memory.
 */

import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { afterEach, describe, expect, it } from "vitest";

import { FetchTimeoutError, fetchBytes, HttpStatusError, ResponseTooLargeError } from "./http";

/**
 * A response whose headers arrive at once but whose body never finishes.
 */
function stallingResponse(firstChunk?: Uint8Array): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      if (firstChunk) {
        controller.enqueue(firstChunk);
      }
      // Never close: the body read stalls forever.
    },
  });

  return new Response(body, { status: 200 });
}

/**
 * A response that streams `chunkCount` chunks of `chunkSize` bytes with no
 * Content-Length header.
 */
function streamingResponse(chunkSize: number, chunkCount: number): Response {
  let sent = 0;

  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= chunkCount) {
        controller.close();

        return;
      }

      sent++;
      controller.enqueue(new Uint8Array(chunkSize));
    },
  });

  return new Response(body, { status: 200 });
}

function fetchReturning(response: () => Response): typeof globalThis.fetch {
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return (async () => response()) as unknown as typeof globalThis.fetch;
}

const limits = { timeout: 100, maxBytes: 1024 };

describe("fetchBytes", () => {
  it("returns the full body of a successful response", async () => {
    const body = new Uint8Array([1, 2, 3, 4]);
    const data = await fetchBytes(
      fetchReturning(() => new Response(body)),
      "http://x/",
      {},
      limits,
    );

    expect(data).toEqual(body);
  });

  it("passes method, headers and body through to fetch", async () => {
    let seen: RequestInit | undefined;

    const fetchFn = (async (_url: string, init?: RequestInit) => {
      seen = init;

      return new Response(new Uint8Array([0]));
    }) as unknown as typeof globalThis.fetch;

    await fetchBytes(
      fetchFn,
      "http://x/",
      { method: "POST", headers: { Accept: "a/b" }, body: new Uint8Array([9]) },
      limits,
    );

    expect(seen?.method).toBe("POST");
    expect(seen?.headers).toEqual({ Accept: "a/b" });
    expect(seen?.signal).toBeInstanceOf(AbortSignal);
  });

  it("rejects when headers arrive but the body stalls", async () => {
    const started = Date.now();

    await expect(
      fetchBytes(
        fetchReturning(() => stallingResponse(new Uint8Array(10))),
        "http://x/",
        {},
        limits,
      ),
    ).rejects.toBeInstanceOf(FetchTimeoutError);

    expect(Date.now() - started).toBeLessThan(2000);
  });

  it("rejects when a custom fetch ignores the abort signal and never answers", async () => {
    const neverAnswers = (() =>
      new Promise<Response>(() => {})) as unknown as typeof globalThis.fetch;

    await expect(fetchBytes(neverAnswers, "http://x/", {}, limits)).rejects.toThrow(
      "Request timed out after 100ms",
    );
  });

  it("aborts the request signal on timeout", async () => {
    let signal: AbortSignal | undefined;

    const fetchFn = (async (_url: string, init?: RequestInit) => {
      signal = init?.signal ?? undefined;

      return stallingResponse();
    }) as unknown as typeof globalThis.fetch;

    await expect(fetchBytes(fetchFn, "http://x/", {}, limits)).rejects.toBeInstanceOf(
      FetchTimeoutError,
    );

    expect(signal?.aborted).toBe(true);
  });

  it("rejects a streamed body larger than maxBytes", async () => {
    await expect(
      fetchBytes(
        fetchReturning(() => streamingResponse(512, 3)),
        "http://x/",
        {},
        limits,
      ),
    ).rejects.toBeInstanceOf(ResponseTooLargeError);
  });

  it("accepts a streamed body of exactly maxBytes", async () => {
    const data = await fetchBytes(
      fetchReturning(() => streamingResponse(512, 2)),
      "http://x/",
      {},
      limits,
    );

    expect(data.byteLength).toBe(1024);
  });

  it("rejects a declared Content-Length larger than maxBytes before reading", async () => {
    const response = () =>
      new Response(stallingResponse().body, { headers: { "Content-Length": "5000" } });

    await expect(
      fetchBytes(fetchReturning(response), "http://x/", {}, { timeout: 10_000, maxBytes: 1024 }),
    ).rejects.toBeInstanceOf(ResponseTooLargeError);
  });

  it("rejects a non-2xx status with HttpStatusError", async () => {
    const error = await fetchBytes(
      fetchReturning(() => new Response("nope", { status: 503, statusText: "Unavailable" })),
      "http://x/",
      {},
      limits,
    ).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(HttpStatusError);
    expect((error as HttpStatusError).status).toBe(503);
    expect((error as HttpStatusError).message).toBe("HTTP 503 Unavailable");
  });

  describe("with the platform fetch against a local server", () => {
    let server: Server | undefined;

    afterEach(async () => {
      if (server) {
        server.closeAllConnections();
        await new Promise(resolve => server?.close(resolve));
        server = undefined;
      }
    });

    async function listen(handler: Parameters<typeof createServer>[1]): Promise<string> {
      server = createServer(handler);

      await new Promise<void>(resolve => server?.listen(0, "127.0.0.1", resolve));

      const { port } = server.address() as AddressInfo;

      return `http://127.0.0.1:${port}/`;
    }

    it("rejects when the server sends headers and then stalls", async () => {
      const url = await listen((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/pkix-cert" });
        res.write(new Uint8Array(16));
        // Never end the response.
      });

      const started = Date.now();

      await expect(
        fetchBytes(globalThis.fetch, url, {}, { timeout: 200, maxBytes: 1024 }),
      ).rejects.toBeInstanceOf(FetchTimeoutError);

      expect(Date.now() - started).toBeLessThan(3000);
    });

    it("rejects when the server streams more than maxBytes", async () => {
      const url = await listen((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/pkix-cert" });
        res.write(new Uint8Array(4096));
        // Never end: the cap must fire without waiting for the end.
      });

      await expect(
        fetchBytes(globalThis.fetch, url, {}, { timeout: 5000, maxBytes: 1024 }),
      ).rejects.toBeInstanceOf(ResponseTooLargeError);
    });

    it("returns the body when the server answers normally", async () => {
      const url = await listen((_req, res) => {
        res.writeHead(200, { "Content-Type": "application/pkix-cert" });
        res.end(new Uint8Array([7, 7, 7]));
      });

      const data = await fetchBytes(globalThis.fetch, url, {}, { timeout: 5000, maxBytes: 1024 });

      expect(data).toEqual(new Uint8Array([7, 7, 7]));
    });
  });
});
