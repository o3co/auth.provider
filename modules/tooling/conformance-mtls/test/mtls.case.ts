import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { areaTarget, type Fake, fakeHttp, type Started } from "@mod/conformance";
import { exportJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { crlOf, type Issued, issue, ocspAnswer, pemOf, thumbprintOf } from "../src/authority.ts";
import { type MtlsPart, mtlsScene } from "../src/main.ts";

/** The code a certificate refused at issuance is answered with, by the target. */
const refusedCertificate = areaTarget().differs("certificate-refused-as-invalid-client")
	? "invalid_certificate"
	: "invalid_client";

const issuer = "https://issuer.example";
const header = "x-client-cert";
const signing = generateKeyPairSync("ed25519");
const secret = "app-secret-0123456789abcdef";
const keys = {
	signing: {
		kid: "mt",
		alg: "EdDSA" as const,
		privatePem: signing.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
		publicPem: signing.publicKey.export({ format: "pem", type: "spki" }).toString(),
	},
};
const clients = [
	{
		id: "app",
		kind: "confidential" as const,
		method: "client_secret_post" as const,
		secret,
		grants: ["client_credentials"],
		scopes: ["read"],
		defaultScopes: ["read"],
		audiences: ["https://api.example"],
	},
];
const loopback = ["127.0.0.1"];
const claimsOf = (jwt: unknown) =>
	JSON.parse(Buffer.from(String(jwt).split(".")[1] ?? "", "base64url").toString()) as Record<
		string,
		unknown
	>;
const pemHeader = (issued: Issued) => ({ [header]: encodeURIComponent(pemOf(issued.der)) });

/** A target set up with this mTLS part, and requests to its token and introspection endpoints. */
function running(part: () => MtlsPart & { readonly dpop?: boolean }) {
	let started: Started;
	const s = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(mtlsScene({ issuer, keys, clients, ...part() }));
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		s.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	const post = async (path: string, form: Record<string, string>, headers = {}) => {
		const res = await fetch(`${s.base}${path}`, {
			method: "POST",
			// As a proxy forwards it, naming the client it serves.
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				"x-forwarded-for": "203.0.113.7",
				...headers,
			},
			body: new URLSearchParams({ client_id: "app", client_secret: secret, ...form }),
		});
		return { status: res.status, body: (await res.json()) as Record<string, unknown> };
	};
	const token = (headers: Record<string, string> = {}) =>
		post("/oauth/token", { grant_type: "client_credentials" }, headers);
	return {
		token,
		introspect: (accessToken: unknown) => post("/oauth/introspect", { token: String(accessToken) }),
		/** Whether a request sending these headers comes away with a token bound to this certificate. */
		boundTo: async (issued: Issued, headers: Record<string, string>) => {
			const answer = await token(headers);
			// A refused request comes away with no token at all.
			if (answer.status !== 200) return false;
			const cnf = claimsOf(answer.body.access_token).cnf as Record<string, unknown> | undefined;
			return cnf?.["x5t#S256"] === thumbprintOf(issued.der);
		},
		discovery: async () =>
			(await (await fetch(`${s.base}/.well-known/openid-configuration`)).json()) as Record<
				string,
				unknown
			>,
	};
}

describe.runIf(areaTarget().can("mtls"))("self-signed certificates", () => {
	const at = running(() => ({
		header: { dialect: "pem", name: header },
		trustedProxies: loopback,
	}));

	it("binds a token to the certificate's thumbprint, as a bearer token, and says so at introspection [rfc8705-3.1-a] [rfc8705-3.1-b] [rfc8705-3.1-c]", async () => {
		const own = await issue({ cn: "client" });
		const answer = await at.token(pemHeader(own));
		const cnf = { "x5t#S256": thumbprintOf(own.der) };
		expect([answer.status, answer.body.token_type]).toEqual([200, "Bearer"]);
		expect(claimsOf(answer.body.access_token).cnf).toEqual(cnf);
		expect((await at.introspect(answer.body.access_token)).body).toMatchObject({
			active: true,
			cnf,
		});
	});

	it("issues an unbound token to a request without a certificate", async () => {
		const answer = await at.token();
		expect([answer.status, answer.body.token_type]).toEqual([200, "Bearer"]);
		expect(claimsOf(answer.body.access_token).cnf).toBeUndefined();
	});

	it("binds nothing to a header holding more than one certificate", async () => {
		const [first, second] = [await issue({ cn: "first" }), await issue({ cn: "second" })];
		const both = { [header]: encodeURIComponent(pemOf(first.der) + pemOf(second.der)) };
		expect(await at.boundTo(first, both)).toBe(false);
		expect(await at.boundTo(second, both)).toBe(false);
	});

	it("says in discovery that it binds access tokens to certificates", async () => {
		expect((await at.discovery()).tls_client_certificate_bound_access_tokens).toBe(true);
	});
});

describe.runIf(areaTarget().can("mtls"))("a peer that is not a trusted proxy", () => {
	const at = running(() => ({
		header: { dialect: "pem", name: header },
		trustedProxies: ["192.0.2.1"],
	}));

	it("binds nothing to the certificate header it sends [rfc8705-3-a]", async () => {
		const own = await issue({ cn: "client" });
		expect(await at.boundTo(own, pemHeader(own))).toBe(false);
	});
});

type Crl = "good" | "revoked" | "down";
type Ocsp = "good" | "revoked" | "unknown" | "down" | "without nonce";

/** A CA whose CRLs and OCSP answers a fake serves, each client certificate at locations of its own. */
const authority = {
	fake: undefined as Fake | undefined,
	root: undefined as Issued | undefined,
	crls: new Map<string, Uint8Array | "down">(),
	answers: new Map<string, Ocsp>(),
	async start() {
		this.fake = await fakeHttp(async (asked) => {
			const crl = this.crls.get(asked.path);
			if (crl) {
				if (crl === "down") return { status: 503 };
				return { headers: { "content-type": "application/pkix-crl" }, bytes: crl };
			}
			const says = this.answers.get(asked.path);
			if (!says) return { status: 404 };
			if (says === "down") return { status: 503 };
			const status = says === "without nonce" ? "good" : says;
			const answer = await ocspAnswer(
				asked.bytes,
				this.root as Issued,
				status,
				says !== "without nonce",
			);
			return { headers: { "content-type": "application/ocsp-response" }, bytes: answer };
		});
		this.root = await issue({ cn: "root", ca: true });
	},
	/** A client certificate whose CRL and OCSP responder say what the scene says, where it names them. */
	async client(says: { readonly crl?: Crl; readonly ocsp?: Ocsp }) {
		const fake = this.fake as Fake;
		const root = this.root as Issued;
		const [crl, ocsp] = [`/crl/${randomUUID()}`, `/ocsp/${randomUUID()}`];
		const issued = await issue({
			cn: "client",
			by: root,
			...(says.crl ? { crl: `${fake.base}${crl}` } : {}),
			...(says.ocsp ? { ocsp: `${fake.base}${ocsp}` } : {}),
		});
		if (says.crl) {
			this.crls.set(
				crl,
				says.crl === "down" ? "down" : await crlOf(root, says.crl === "revoked" ? [issued] : []),
			);
		}
		if (says.ocsp) this.answers.set(ocsp, says.ocsp);
		return issued;
	},
	part(mode: "crl" | "ocsp" | "both", onUnavailable: "reject" | "allow"): MtlsPart {
		return {
			header: { dialect: "pem", name: header },
			trustedProxies: loopback,
			pki: {
				anchors: [pemOf((this.root as Issued).der)],
				revocation: { mode, onUnavailable, sources: [new URL((this.fake as Fake).base).host] },
			},
		};
	},
};
beforeAll(() => authority.start());
afterAll(() => authority.fake?.stop());

describe.runIf(areaTarget().can("mtls"))("certificates under PKI, revocation by CRL", () => {
	const at = running(() => authority.part("crl", "reject"));

	it("binds a certificate whose path reaches the anchor and whose CRL does not list it", async () => {
		const good = await authority.client({ crl: "good" });
		expect(await at.boundTo(good, pemHeader(good))).toBe(true);
	});

	it("refuses a certificate its CRL lists, or one from another authority", async () => {
		const revoked = await authority.client({ crl: "revoked" });
		const listed = await at.token(pemHeader(revoked));
		expect([listed.status, listed.body.error]).toEqual([400, refusedCertificate]);
		const stranger = await issue({ cn: "client", by: await issue({ cn: "root", ca: true }) });
		const foreign = await at.token(pemHeader(stranger));
		expect([foreign.status, foreign.body.error]).toEqual([400, refusedCertificate]);
	});

	it("answers unavailable while the CRL cannot be fetched, when told to reject", async () => {
		const down = await authority.client({ crl: "down" });
		const answer = await at.token(pemHeader(down));
		expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
	});
});

describe.runIf(areaTarget().can("mtls"))(
	"certificates under PKI, allowing what cannot be confirmed",
	() => {
		const at = running(() => authority.part("crl", "allow"));

		it("binds a certificate while its CRL cannot be fetched, and still refuses one it lists", async () => {
			const down = await authority.client({ crl: "down" });
			expect(await at.boundTo(down, pemHeader(down))).toBe(true);
			const revoked = await authority.client({ crl: "revoked" });
			expect((await at.token(pemHeader(revoked))).status).toBe(400);
		});
	},
);

describe.runIf(areaTarget().can("mtls"))("certificates under PKI, revocation by OCSP", () => {
	const at = running(() => authority.part("ocsp", "reject"));

	it("binds a certificate its responder answers good for, with the nonce asked", async () => {
		const good = await authority.client({ ocsp: "good" });
		expect(await at.boundTo(good, pemHeader(good))).toBe(true);
	});

	it("refuses one answered revoked or unknown, or answered without the nonce asked", async () => {
		for (const says of ["revoked", "unknown", "without nonce"] as const) {
			const issued = await authority.client({ ocsp: says });
			const answer = await at.token(pemHeader(issued));
			expect([answer.status, answer.body.error], says).toEqual([400, refusedCertificate]);
		}
	});

	it("answers unavailable while the responder is down, when told to reject", async () => {
		const down = await authority.client({ ocsp: "down" });
		const answer = await at.token(pemHeader(down));
		expect([answer.status, answer.body.error]).toEqual([503, "temporarily_unavailable"]);
	});
});

describe.runIf(areaTarget().can("mtls"))(
	"certificates under PKI, OCSP allowing what cannot be confirmed",
	() => {
		const at = running(() => authority.part("ocsp", "allow"));

		it("binds one while the responder is down", async () => {
			const down = await authority.client({ ocsp: "down" });
			expect(await at.boundTo(down, pemHeader(down))).toBe(true);
		});
	},
);

describe.runIf(areaTarget().can("mtls"))(
	"certificates under PKI, revocation by OCSP and then CRL",
	() => {
		const at = running(() => authority.part("both", "reject"));

		it("falls back to the CRL while the responder is down", async () => {
			const good = await authority.client({ ocsp: "down", crl: "good" });
			expect(await at.boundTo(good, pemHeader(good))).toBe(true);
			const revoked = await authority.client({ ocsp: "down", crl: "revoked" });
			expect((await at.token(pemHeader(revoked))).status).toBe(400);
		});

		it("lets the CRL only add a revocation to an unknown, never clear it", async () => {
			for (const crl of ["good", "revoked"] as const) {
				const issued = await authority.client({ ocsp: "unknown", crl });
				const answer = await at.token(pemHeader(issued));
				expect([answer.status, answer.body.error], crl).toEqual([400, refusedCertificate]);
			}
		});
	},
);

const holder = generateKeyPairSync("ed25519");
async function proof() {
	return new SignJWT({
		htm: "POST",
		htu: `${issuer}/oauth/token`,
		iat: Math.floor(Date.now() / 1000),
		jti: randomUUID(),
	})
		.setProtectedHeader({ alg: "EdDSA", typ: "dpop+jwt", jwk: await exportJWK(holder.publicKey) })
		.sign(holder.privateKey);
}

describe.runIf(areaTarget().can("mtls") && areaTarget().can("dpop"))("mTLS beside DPoP", () => {
	const at = running(() => ({
		header: { dialect: "pem", name: header },
		trustedProxies: loopback,
		dpop: true,
	}));

	it("takes the DPoP proof over the certificate of a request proving both, as 0.17 does by default", async () => {
		const own = await issue({ cn: "client" });
		const answer = await at.token({ ...pemHeader(own), dpop: await proof() });
		expect([answer.status, answer.body.token_type]).toEqual([200, "DPoP"]);
	});
});

const xfcc = "x-forwarded-client-cert";
const sha256 = (der: Uint8Array) => createHash("sha256").update(der).digest("hex");
const element = (issued: Issued, more = "") =>
	`Hash=${sha256(issued.der)};Cert="${encodeURIComponent(pemOf(issued.der))}"${more}`;

describe.runIf(areaTarget().can("mtls"))("Envoy's XFCC header", () => {
	const at = running(() => ({ header: { dialect: "xfcc", name: xfcc }, trustedProxies: loopback }));

	it("binds the certificate of the one element the proxy sets", async () => {
		const own = await issue({ cn: "client" });
		expect(
			await at.boundTo(own, { [xfcc]: `By=spiffe://proxy;${element(own)};DNS=a.example` }),
		).toBe(true);
	});

	it("binds nothing to a certificate written inside a quoted value", async () => {
		const [own, other] = [await issue({ cn: "client" }), await issue({ cn: "other" })];
		const inside = `Subject="CN=x;Cert=${encodeURIComponent(pemOf(other.der))}";${element(own)}`;
		expect(await at.boundTo(other, { [xfcc]: inside })).toBe(false);
	});

	it("binds nothing when Cert comes twice, in any case, nor when the Hash is another's", async () => {
		const [own, other] = [await issue({ cn: "client" }), await issue({ cn: "other" })];
		const twice = element(own, `;cert="${encodeURIComponent(pemOf(other.der))}"`);
		for (const issued of [own, other])
			expect(await at.boundTo(issued, { [xfcc]: twice })).toBe(false);
		const mismatched = `Hash=${sha256(other.der)};Cert="${encodeURIComponent(pemOf(own.der))}"`;
		expect(await at.boundTo(own, { [xfcc]: mismatched })).toBe(false);
	});
});
