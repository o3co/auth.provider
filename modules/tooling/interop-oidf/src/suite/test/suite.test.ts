import { X509Certificate } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { type AddressInfo, createServer as createTcpServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { describe, expect, it } from "vitest";
import {
	certificateAt,
	composeOverride,
	getJson,
	pemOf,
	pinnedTo,
	projectOf,
	suiteEnv,
	suiteOrigin,
} from "../suite.ts";

describe("the suite, as the harness starts it", () => {
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

	it("lets the suite's server reach this machine by name, in IPv4 alone", () => {
		const linux = composeOverride({
			name: "host.docker.internal",
			listen: "172.17.0.1",
			mapped: "172.17.0.1",
		});
		expect(linux).toContain(
			'  server:\n    extra_hosts:\n      - "host.docker.internal:172.17.0.1"\n',
		);
		expect(linux).not.toContain("host-gateway");
		// Docker Desktop names the machine itself.
		expect(composeOverride({ name: "host.docker.internal", listen: "127.0.0.1" })).not.toContain(
			"server:",
		);
	});

	it("keeps the suite's store in memory, never in a directory of this machine", () => {
		for (const host of [
			{ name: "h", listen: "127.0.0.1" },
			{ name: "h", listen: "1.2.3.4", mapped: "1.2.3.4" },
		]) {
			expect(composeOverride(host)).toMatch(
				/^services:\n {2}mongodb:\n {4}volumes:\n {6}- type: tmpfs\n {8}target: \/data\/db\n/,
			);
		}
	});

	it("takes the certificate first read alone, by its fingerprint, whatever host it names", async () => {
		const dir = await mkdtemp(join(tmpdir(), "suite-"));
		const first = await selfSigned("localhost", join(dir, "first"));
		const other = await selfSigned("localhost", join(dir, "other"));
		const check = pinnedTo(first.cert);
		const of = (pem: string) => ({ fingerprint256: new X509Certificate(pem).fingerprint256 });
		expect(check("localhost.emobix.co.uk", of(first.cert))).toBeUndefined();
		expect(check("localhost.emobix.co.uk", of(other.cert))).toBeInstanceOf(Error);
	});

	it("names the suite's origin itself, whatever the runner's environment holds", () => {
		const before = process.env.BASE_URL;
		process.env.BASE_URL = "/";
		try {
			const env = suiteEnv({ tag: "release-v1", commit: "c", python: [] });
			expect(env.BASE_URL).toBe(suiteOrigin);
			expect(env.BASE_MTLS_URL).toBe("https://localhost.emobix.co.uk:8444");
			expect(env.IMAGE_TAG).toBe("release-v1");
		} finally {
			if (before === undefined) delete process.env.BASE_URL;
			else process.env.BASE_URL = before;
		}
	});

	it("gives each start a Compose project of its own, though every start's directory is named alike", () => {
		const one = projectOf(join("/tmp/interop-oidf-basic-a1", "suite"));
		const other = projectOf(join("/tmp/interop-oidf-basic-b2", "suite"));
		expect(one).not.toBe(other);
		for (const name of [one, other]) expect(name).toMatch(/^o3co-oidf-[a-z0-9]+$/);
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
});
