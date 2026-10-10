/**
 * Tests that a caller-supplied `fetch` reaches every network request LibPDF
 * makes itself while gathering long-term validation data.
 *
 * The global fetch is replaced with one that fails the test, so any request
 * that bypasses the caller's fetch is caught without touching the network.
 */

import { toArrayBuffer } from "#src/helpers/buffer.ts";
import type { Signer, TimestampAuthority } from "#src/signatures/types";
import { loadFixture } from "#src/test-utils";
import { fromBER, OctetString } from "asn1js";
import * as pkijs from "pkijs";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { PDF } from "./pdf";

const LEAF_AIA_URL = "http://crt.sectigo.com/SectigoPublicServerAuthenticationCADVE36.crt";
const LEAF_OCSP_URL = "http://ocsp.sectigo.com";

async function loadRealCert(name: string): Promise<Uint8Array> {
  return loadFixture("certificates", `real/${name}`);
}

/**
 * A signer whose certificate carries AIA and OCSP URLs. The signature value
 * is a placeholder: nothing here verifies it.
 */
function createSigner(certificate: Uint8Array, certificateChain?: Uint8Array[]): Signer {
  return {
    certificate,
    certificateChain,
    keyType: "EC",
    signatureAlgorithm: "ECDSA",
    sign: async () => new Uint8Array(72),
  };
}

/**
 * A minimal CMS SignedData carrying `certificate`, used as a stand-in
 * timestamp token so the timestamp's LTV path runs.
 */
function createCms(certificate: Uint8Array): Uint8Array {
  const cert = new pkijs.Certificate({ schema: fromBER(toArrayBuffer(certificate)).result });

  const signerInfo = new pkijs.SignerInfo({
    version: 1,
    sid: new pkijs.IssuerAndSerialNumber({
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
    }),
  });

  signerInfo.digestAlgorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: "2.16.840.1.101.3.4.2.1",
  });
  signerInfo.signatureAlgorithm = new pkijs.AlgorithmIdentifier({
    algorithmId: "1.2.840.10045.4.3.2",
  });
  signerInfo.signature = new OctetString({ valueHex: new ArrayBuffer(72) });

  const signedData = new pkijs.SignedData({
    version: 1,
    certificates: [cert],
    signerInfos: [signerInfo],
  });

  signedData.encapContentInfo = new pkijs.EncapsulatedContentInfo({
    eContentType: "1.2.840.113549.1.9.16.1.4",
  });
  signedData.digestAlgorithms = [
    new pkijs.AlgorithmIdentifier({ algorithmId: "2.16.840.1.101.3.4.2.1" }),
  ];

  const contentInfo = new pkijs.ContentInfo({
    contentType: "1.2.840.113549.1.7.2",
    content: signedData.toSchema(true),
  });

  return new Uint8Array(contentInfo.toSchema().toBER(false));
}

/**
 * A fetch that records each request and serves the leaf's issuer over AIA.
 */
function createRecordingFetch(issuer: Uint8Array) {
  const requests: { url: string; method: string }[] = [];

  const fetchFn = (async (url: string, init?: RequestInit) => {
    requests.push({ url, method: init?.method ?? "GET" });

    if (url === LEAF_AIA_URL) {
      return new Response(issuer, { status: 200 });
    }

    return new Response(null, { status: 404 });
  }) as unknown as typeof globalThis.fetch;

  return { fetch: fetchFn, requests };
}

const noRevocation = {
  getOCSP: async () => null,
  getCRL: async () => null,
};

describe("PDFSignature custom fetch", () => {
  let globalFetchCalls: string[];
  let leaf: Uint8Array;
  let issuer: Uint8Array;

  beforeEach(async () => {
    globalFetchCalls = [];
    leaf = await loadRealCert("github-0.der");
    issuer = await loadRealCert("github-1.der");

    vi.stubGlobal("fetch", async (url: string) => {
      globalFetchCalls.push(String(url));

      throw new Error(`global fetch used for ${String(url)}`);
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function loadPdf(): Promise<PDF> {
    return PDF.load(await loadFixture("basic", "rot0.pdf"));
  }

  function tsaFor(certificate: Uint8Array): TimestampAuthority {
    return { timestamp: async () => createCms(certificate) };
  }

  it("sign() uses it for the AIA issuer fetch", async () => {
    const pdf = await loadPdf();
    const recording = createRecordingFetch(issuer);

    await pdf.sign({
      signer: createSigner(leaf),
      longTermValidation: true,
      revocationProvider: noRevocation,
      fetch: recording.fetch,
    });

    expect(recording.requests.map(r => r.url)).toContain(LEAF_AIA_URL);
    expect(globalFetchCalls).toEqual([]);
  });

  it("sign() uses it for default OCSP requests when no revocationProvider is given", async () => {
    const pdf = await loadPdf();
    const recording = createRecordingFetch(issuer);

    // Embed the issuer so OCSP has it even though the root's AIA fetch 404s.
    await pdf.sign({
      signer: createSigner(leaf, [issuer]),
      longTermValidation: true,
      fetch: recording.fetch,
    });

    expect(recording.requests).toContainEqual({ url: LEAF_OCSP_URL, method: "POST" });
    expect(globalFetchCalls).toEqual([]);
  });

  it("sign() at B-LTA uses it for the document timestamp's LTV data", async () => {
    const pdf = await loadPdf();
    const recording = createRecordingFetch(issuer);

    await pdf.sign({
      signer: createSigner(leaf),
      level: "B-LTA",
      timestampAuthority: tsaFor(leaf),
      revocationProvider: noRevocation,
      fetch: recording.fetch,
    });

    // Signature, its embedded timestamp, and the document timestamp.
    const aiaFetches = recording.requests.filter(r => r.url === LEAF_AIA_URL);

    expect(aiaFetches.length).toBeGreaterThanOrEqual(3);
    expect(globalFetchCalls).toEqual([]);
  });

  it("addValidationData() uses it", async () => {
    const pdf = await loadPdf();

    await pdf.sign({ signer: createSigner(leaf, [issuer]) });

    const recording = createRecordingFetch(issuer);
    const { signatureCount } = await pdf.addValidationData({ fetch: recording.fetch });

    expect(signatureCount).toBe(1);
    // The chain continues from the embedded issuer to the root's AIA URL.
    expect(recording.requests.some(r => r.url.startsWith("http://crt.sectigo.com/"))).toBe(true);
    expect(recording.requests).toContainEqual({ url: LEAF_OCSP_URL, method: "POST" });
    expect(globalFetchCalls).toEqual([]);
  });

  it("addTimestamp() uses it for the timestamp's LTV data", async () => {
    const pdf = await loadPdf();
    const recording = createRecordingFetch(issuer);

    await pdf.addTimestamp({
      timestampAuthority: tsaFor(leaf),
      longTermValidation: true,
      fetch: recording.fetch,
    });

    expect(recording.requests.map(r => r.url)).toContain(LEAF_AIA_URL);
    expect(globalFetchCalls).toEqual([]);
  });

  it("addArchivalData() uses it for both steps", async () => {
    const pdf = await loadPdf();

    await pdf.sign({ signer: createSigner(leaf) });

    const recording = createRecordingFetch(issuer);

    await pdf.addArchivalData({
      timestampAuthority: tsaFor(leaf),
      revocationProvider: noRevocation,
      fetch: recording.fetch,
    });

    expect(recording.requests.filter(r => r.url === LEAF_AIA_URL).length).toBeGreaterThanOrEqual(2);
    expect(globalFetchCalls).toEqual([]);
  });
});
