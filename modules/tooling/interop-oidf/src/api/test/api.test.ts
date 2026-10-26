import { X509Certificate } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { type AddressInfo, createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { describe, expect, it } from "vitest";
import { certificateAt, getJson, pemOf, pinnedTo } from "../api.ts";

describe("the suite's API, reached trusting its certificate alone", () => {
	it("takes the certificate first read alone, by its fingerprint, whatever host it names", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-"));
		const first = await selfSigned("localhost", join(dir, "first"));
		const other = await selfSigned("localhost", join(dir, "other"));
		const check = pinnedTo(first.cert);
		const of = (pem: string) => ({ fingerprint256: new X509Certificate(pem).fingerprint256 });
		expect(check("localhost.emobix.co.uk", of(first.cert))).toBeUndefined();
		expect(check("localhost.emobix.co.uk", of(other.cert))).toBeInstanceOf(Error);
	});
	it("gives up on a suite that takes the connection and never finishes the TLS handshake", async () => {
		const silent = createTcpServer(() => {});
		await new Promise<void>((resolve) => silent.listen(0, "127.0.0.1", resolve));
		const port = (silent.address() as AddressInfo).port;
		try {
			await expect(certificateAt({ host: "127.0.0.1", port }, 200)).rejects.toThrow();
		} finally {
			silent.close();
		}
	});
	it("refuses an answer the suite cuts off midway, never left pending", async () => {
		const tls = await selfSigned("localhost", await mkdtemp(join(tmpdir(), "suite-")));
		const cut = createHttpsServer(tls, (_req, res) => {
			res.writeHead(200, { "content-type": "application/json", "content-length": "100" });
			res.write('{"part');
			setTimeout(() => res.socket?.destroy(), 50);
		});
		await new Promise<void>((resolve) => cut.listen(0, "127.0.0.1", resolve));
		const port = (cut.address() as AddressInfo).port;
		try {
			const settled = await Promise.race([
				getJson(`https://localhost:${port}/api/plan`, tls.cert).then(
					() => "answered",
					() => "refused",
				),
				new Promise((resolve) => setTimeout(() => resolve("pending"), 3_000)),
			]);
			expect(settled).toBe("refused");
		} finally {
			cut.closeAllConnections();
			cut.close();
		}
	});
	it("gives up on an answer that trickles in past its time, and where the deadline aborts", async () => {
		const tls = await selfSigned("localhost", await mkdtemp(join(tmpdir(), "suite-")));
		// A part of the JSON every 50ms, never the whole: the socket is never idle.
		const drip = createHttpsServer(tls, (_req, res) => {
			res.writeHead(200, { "content-type": "application/json" });
			res.write("[");
			const timer = setInterval(() => res.write("0,"), 50);
			res.on("close", () => clearInterval(timer));
		});
		await new Promise<void>((resolve) => drip.listen(0, "127.0.0.1", resolve));
		const url = `https://localhost:${(drip.address() as AddressInfo).port}/api/plan`;
		const settled = (answer: Promise<unknown>) =>
			Promise.race([
				answer.then(
					() => "answered",
					() => "refused",
				),
				new Promise((resolve) => setTimeout(() => resolve("pending"), 3_000)),
			]);
		try {
			expect(await settled(getJson(url, tls.cert, { withinMs: 300 }))).toBe("refused");
			expect(await settled(getJson(url, tls.cert, { signal: AbortSignal.timeout(300) }))).toBe(
				"refused",
			);
		} finally {
			drip.closeAllConnections();
			drip.close();
		}
	});
	it("writes the certificate its nginx answers with as PEM, the same certificate", async () => {
		const { cert } = await selfSigned("suite.test", await mkdtemp(join(tmpdir(), "suite-")));
		const raw = new X509Certificate(cert).raw;
		const written = pemOf(raw);
		expect(written).toMatch(
			/^-----BEGIN CERTIFICATE-----\n([A-Za-z0-9+/=]{1,64}\n)+-----END CERTIFICATE-----\n$/,
		);
		expect(new X509Certificate(written).fingerprint256).toBe(
			new X509Certificate(cert).fingerprint256,
		);
	});
});
