import { describe, expect, it } from "vitest";
import type { HttpRequest } from "../../contract.ts";
import { handlers, serveWith, warning } from "./serve.ts";

describe("the client's certificate", () => {
	const der = Uint8Array.from([48, 3, 2, 1, 1]);
	const sent = { "client-cert": `:${Buffer.from(der).toString("base64")}:` };
	let seen: HttpRequest["source"]["clientCertificate"];
	const reading = handlers([
		{
			method: "GET",
			path: "/",
			handle: (request) => {
				seen = request.source.clientCertificate;
				return { status: 204 };
			},
		},
	]);
	const forwarding = (trusted: string[]) => ({
		"trusted-proxies": trusted,
		"client-certificate": { dialect: "rfc9440" },
	});

	it("is handed to a handler as a trusted proxy forwards it, with no warning", async () => {
		const { runtime, count } = warning();
		await fetch(await serveWith(reading, forwarding(["127.0.0.1"]), runtime), { headers: sent });
		expect(seen).toEqual({ kind: "certificate", leaf: der, chain: [] });
		expect(count("http.client_certificate_ignored")).toBe(0);
	});

	it("is ignored from a peer not trusted, with a warning once a minute", async () => {
		const { runtime, count } = warning();
		const base = await serveWith(reading, forwarding([]), runtime);
		await fetch(base, { headers: sent });
		expect(seen).toBeUndefined();
		await fetch(base, { headers: sent });
		expect(count("http.client_certificate_ignored")).toBe(1);
	});
});
