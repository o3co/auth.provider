import { X509Certificate } from "node:crypto";
import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";
import { describe, expect, it } from "vitest";
import { composeOverride, pinnedTo, suiteEnv, suiteOrigin } from "../suite.ts";

const files = { cert: "/run/nginx-cert.pem", key: "/run/nginx-key.pem" };

describe("the suite, as the harness starts it", () => {
	it("lets the suite's server reach this machine by name, in IPv4 alone", () => {
		const linux = composeOverride(
			{ name: "host.docker.internal", listen: "172.17.0.1", mapped: "172.17.0.1" },
			files,
		);
		expect(linux).toContain(
			'  server:\n    extra_hosts:\n      - "host.docker.internal:172.17.0.1"\n',
		);
		expect(linux).not.toContain("host-gateway");
		// Docker Desktop names the machine itself.
		expect(
			composeOverride({ name: "host.docker.internal", listen: "127.0.0.1" }, files),
		).not.toContain("server:");
	});

	it("keeps the suite's store in memory, never in a directory of this machine", () => {
		for (const host of [
			{ name: "h", listen: "127.0.0.1" },
			{ name: "h", listen: "1.2.3.4", mapped: "1.2.3.4" },
		]) {
			expect(composeOverride(host, files)).toMatch(
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

	it("has the suite's nginx answer with the harness's certificate, read only", () => {
		const text = composeOverride({ name: "h", listen: "127.0.0.1" }, files);
		expect(text).toContain(
			"  nginx:\n    volumes:\n      - type: bind\n        source: /run/nginx-cert.pem\n        target: /etc/ssl/certs/nginx-selfsigned.crt\n        read_only: true\n",
		);
		expect(text).toContain(
			"        source: /run/nginx-key.pem\n        target: /etc/ssl/private/nginx-selfsigned.key\n        read_only: true\n",
		);
	});
});
