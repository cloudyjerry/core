/**
 * Bounded HTTP fetching for signature-related network requests.
 *
 * AIA issuer certificates, OCSP responses, CRLs and timestamp tokens are all
 * fetched from servers named inside certificates or chosen by the caller.
 * A server that sends response headers and then stalls (or streams an
 * unbounded body) must not be able to hang signing or exhaust memory, so
 * the timeout here covers the WHOLE request - connection, headers and the
 * full body read - and the body is capped at a fixed number of bytes.
 */

/** Maximum size of a fetched certificate (AIA caIssuers). */
export const MAX_CERTIFICATE_BYTES = 1024 * 1024;

/** Maximum size of a fetched OCSP response. */
export const MAX_OCSP_RESPONSE_BYTES = 1024 * 1024;

/** Maximum size of a fetched timestamp response. */
export const MAX_TIMESTAMP_RESPONSE_BYTES = 1024 * 1024;

/**
 * Maximum size of a fetched CRL. CRLs for large CAs can legitimately run to
 * tens of megabytes, so this cap is far looser than the others.
 */
export const MAX_CRL_BYTES = 64 * 1024 * 1024;

/**
 * The request did not complete (headers and body) within the timeout.
 */
export class FetchTimeoutError extends Error {
  readonly timeout: number;

  constructor(timeout: number) {
    super(`Request timed out after ${timeout}ms`);
    this.name = "FetchTimeoutError";
    this.timeout = timeout;
  }
}

/**
 * The response body exceeded the allowed size.
 */
export class ResponseTooLargeError extends Error {
  readonly maxBytes: number;

  constructor(maxBytes: number) {
    super(`Response body exceeds ${maxBytes} bytes`);
    this.name = "ResponseTooLargeError";
    this.maxBytes = maxBytes;
  }
}

/**
 * The server answered with a non-2xx status.
 */
export class HttpStatusError extends Error {
  readonly status: number;
  readonly statusText: string;

  constructor(status: number, statusText: string) {
    super(`HTTP ${status} ${statusText}`.trimEnd());
    this.name = "HttpStatusError";
    this.status = status;
    this.statusText = statusText;
  }
}

/**
 * Limits applied to a bounded fetch.
 */
export interface FetchBytesLimits {
  /** Time allowed for the whole request, including reading the body, in ms. */
  timeout: number;

  /** Maximum number of body bytes to accept. */
  maxBytes: number;
}

/**
 * Fetch a URL and read the full response body, bounded in time and size.
 *
 * The timeout stays armed until the body has been read completely. It is
 * enforced both by aborting the request's signal and by racing the result,
 * so it also holds for a custom fetch that ignores `signal`.
 *
 * @throws {FetchTimeoutError} if the request or body read exceeds `timeout`
 * @throws {ResponseTooLargeError} if the body exceeds `maxBytes`
 * @throws {HttpStatusError} if the response status is not 2xx
 */
export async function fetchBytes(
  fetchFn: typeof globalThis.fetch,
  url: string,
  init: Omit<RequestInit, "signal">,
  limits: FetchBytesLimits,
): Promise<Uint8Array> {
  const controller = new AbortController();
  let timeoutId: ReturnType<typeof setTimeout> | undefined;

  const timedOut = new Promise<never>((_resolve, reject) => {
    timeoutId = setTimeout(() => {
      const error = new FetchTimeoutError(limits.timeout);

      reject(error);
      controller.abort(error);
    }, limits.timeout);
  });

  // The race below may settle first; never leave this rejection unhandled.
  timedOut.catch(() => {});

  try {
    const response = await Promise.race([
      fetchFn(url, { ...init, signal: controller.signal }),
      timedOut,
    ]);

    if (!response.ok) {
      response.body?.cancel().catch(() => {});

      throw new HttpStatusError(response.status, response.statusText);
    }

    return await Promise.race([readBody(response, limits.maxBytes, controller.signal), timedOut]);
  } catch (error) {
    // Some fetch implementations reject with their own AbortError when the
    // signal fires; report it as the timeout it is.
    if (controller.signal.aborted && !(error instanceof FetchTimeoutError)) {
      throw new FetchTimeoutError(limits.timeout);
    }

    throw error;
  } finally {
    clearTimeout(timeoutId);
    controller.abort();
  }
}

/**
 * Read a response body into memory, rejecting once it exceeds `maxBytes`.
 */
async function readBody(
  response: Response,
  maxBytes: number,
  signal: AbortSignal,
): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");

  if (declaredLength !== null && Number(declaredLength) > maxBytes) {
    response.body?.cancel().catch(() => {});

    throw new ResponseTooLargeError(maxBytes);
  }

  if (!response.body) {
    const data = new Uint8Array(await response.arrayBuffer());

    if (data.byteLength > maxBytes) {
      throw new ResponseTooLargeError(maxBytes);
    }

    return data;
  }

  const reader = response.body.getReader();
  const cancelOnAbort = () => {
    reader.cancel(signal.reason).catch(() => {});
  };

  signal.addEventListener("abort", cancelOnAbort, { once: true });

  const chunks: Uint8Array[] = [];
  let total = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();

      if (signal.aborted) {
        throw signal.reason;
      }

      if (done) {
        break;
      }

      total += value.byteLength;

      if (total > maxBytes) {
        reader.cancel().catch(() => {});

        throw new ResponseTooLargeError(maxBytes);
      }

      chunks.push(value);
    }
  } finally {
    signal.removeEventListener("abort", cancelOnAbort);
  }

  const data = new Uint8Array(total);
  let offset = 0;

  for (const chunk of chunks) {
    data.set(chunk, offset);
    offset += chunk.byteLength;
  }

  return data;
}
