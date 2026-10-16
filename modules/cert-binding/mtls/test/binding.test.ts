import { createHash } from "node:crypto";
import type { Scene } from "@mod/sender-binding";
import { describe, expect, it } from "vitest";
import { type Checking, readCertificate } from "../src/binding.ts";
import type { Checked } from "../src/pki/contract.ts";
import { issue } from "../src/pki/test/authority.ts";

const thumbprint = (der: Uint8Array) => createHash("sha256").update(der).digest("base64url");
const issuance: Scene = { kind: "issue" };
/** Bytes that are no certificate; the stand-in checks never parse them. */
const opaque = {
	kind: "certificate" as const,
	leaf: new Uint8Array([7, 7, 7]),
	chain: [new Uint8Array([8])],
};

/** Reading under checks that answer as told, recording what they were asked. */
function under(checked?: Checked, onUnavailable: "reject" | "allow" = "reject") {
	const logged: string[] = [];
	const asked: unknown[] = [];
	const checking: Checking = {
		now: () => 1234,
		log: (event) => void logged.push(event),
		...(checked
			? {
					pki: {
						checks: {
							check: async (leaf, chain, now) => {
								asked.push([leaf, chain, now]);
								return checked;
							},
						},
						onUnavailable,
					},
				}
			: {}),
	};
	return {
		read: (scene = issuance) => readCertificate(opaque, scene, checking),
		checking,
		logged,
		asked,
	};
}

describe("reading the client's certificate", () => {
	it("binds nothing without a certificate", async () => {
		expect(await readCertificate(undefined, issuance, under().checking)).toEqual({
			kind: "absent",
		});
	});

	it("refuses a certificate the proxy forwarded unreadable, under either mode", async () => {
		for (const checking of [under().checking, under({ kind: "valid" }).checking]) {
			expect(await readCertificate({ kind: "malformed" }, issuance, checking)).toMatchObject({
				kind: "refused",
				error: "invalid_certificate",
			});
		}
	});

	it("binds a self-signed certificate by its thumbprint, once it parses", async () => {
		const own = await issue({ cn: "client" });
		const forwarded = { kind: "certificate" as const, leaf: own.der, chain: [] };
		expect(await readCertificate(forwarded, issuance, under().checking)).toEqual({
			kind: "bound",
			confirmation: thumbprint(own.der),
		});
		const { read, logged } = under();
		expect(await read()).toEqual({
			kind: "refused",
			error: "invalid_certificate",
			description: "certificate refused",
		});
		expect(logged).toEqual(["mtls.certificate_refused"]);
	});

	it("binds under PKI what the checks find valid, asking about the certificate as sent", async () => {
		const { read, asked } = under({ kind: "valid" });
		expect(await read()).toEqual({ kind: "bound", confirmation: thumbprint(opaque.leaf) });
		expect(asked).toEqual([[opaque.leaf, opaque.chain, 1234]]);
		for (const checked of [{ kind: "revoked" }, { kind: "invalid", reason: "path" }] as const) {
			const refusing = under(checked, "allow");
			expect(await refusing.read()).toMatchObject({
				kind: "refused",
				error: "invalid_certificate",
			});
			expect(refusing.logged).toEqual(["mtls.certificate_refused"]);
		}
	});

	it("leaves an outage to the operator: unavailable when rejecting, bound and logged when allowing", async () => {
		const down = { kind: "outage", reason: "unreachable" } as const;
		expect(await under(down, "reject").read()).toEqual({
			kind: "refused",
			error: "temporarily_unavailable",
			description: "revocation not confirmed",
			unavailable: true,
		});
		const allowing = under(down, "allow");
		expect(await allowing.read()).toEqual({ kind: "bound", confirmation: thumbprint(opaque.leaf) });
		expect(allowing.logged).toEqual(["mtls.revocation_unconfirmed"]);
	});

	it("answers a refusal at a resource as an invalid token, and an outage as unavailable still", async () => {
		const resource: Scene = { kind: "resource", token: "t" };
		expect(await readCertificate({ kind: "malformed" }, resource, under().checking)).toMatchObject({
			kind: "refused",
			error: "invalid_token",
		});
		expect(await under().read(resource)).toMatchObject({ kind: "refused", error: "invalid_token" });
		for (const checked of [{ kind: "revoked" }, { kind: "invalid", reason: "path" }] as const) {
			expect(await under(checked).read(resource)).toMatchObject({
				kind: "refused",
				error: "invalid_token",
			});
		}
		const down = { kind: "outage", reason: "unreachable" } as const;
		expect(await under(down).read(resource)).toMatchObject({
			error: "temporarily_unavailable",
			unavailable: true,
		});
	});
});
