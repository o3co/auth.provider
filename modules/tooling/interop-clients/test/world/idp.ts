import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { selfSigned } from "@mod/conformance-front";

const exchangeGrant = "urn:ietf:params:oauth:grant-type:token-exchange";
const idJagType = "urn:ietf:params:oauth:token-type:id-jag";

/** What the next ID-JAG the IdP issues says otherwise than it would: for the checks of what is refused. */
export interface Otherwise {
	readonly typ?: string;
	readonly aud?: string;
	readonly clientId?: string;
}

/**
 * An enterprise IdP the harness plays: it answers a token exchange asking for an ID-JAG with one it
 * signs (draft-ietf-oauth-identity-assertion-authz-grant-04 §4.3), for the audience asked and the
 * client that asked, bound to the DPoP key the request proves where it sends one. It checks nothing
 * of the client or subject token: what is checked is the provider's taking of the ID-JAG.
 */
export interface PlayedIdp {
	readonly issuer: string;
	/** Its certificate, as PEM, which the adapter trusts beside the front's. */
	readonly ca: string;
	/** Its signing key, as SPKI PEM, which the provider's trusted issuer is written with. */
	readonly publicPem: string;
	/** The next ID-JAG is otherwise as told, once. */
	otherwise(next: Otherwise): void;
	/** The claims of each ID-JAG it issued, in order. */
	issued(): readonly Readonly<Record<string, unknown>>[];
	stop(): Promise<void>;
}

const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");

/** The RFC 7638 thumbprint of an EC or OKP public JWK, the `jkt` a DPoP proof's key gives. */
function thumbprintOf(jwk: Record<string, unknown>): string {
	const members =
		jwk.kty === "EC"
			? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
			: { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
	return createHash("sha256").update(JSON.stringify(members)).digest("base64url");
}

/** The key a DPoP proof's header names, read unverified: the played IdP takes the client's word. */
function proofKey(proof: string | undefined): string | undefined {
	if (!proof) return undefined;
	try {
		const header = JSON.parse(Buffer.from(proof.split(".")[0] ?? "", "base64url").toString());
		return header.jwk ? thumbprintOf(header.jwk) : undefined;
	} catch {
		return undefined;
	}
}

export async function startPlayedIdp(under?: string): Promise<PlayedIdp> {
	const key = generateKeyPairSync("ec", { namedCurve: "P-256" });
	// Its certificate's files are read back as PEM and gone before it listens.
	const dir = await mkdtemp(join(under ?? tmpdir(), "interop-idp-"));
	const tls = await selfSigned("127.0.0.1", dir).finally(() =>
		rm(dir, { recursive: true, force: true }),
	);
	let origin = "";
	let next: Otherwise = {};
	const issued: Record<string, unknown>[] = [];
	const server = createServer(tls, (req, res) => {
		const json = (status: number, value: unknown) => {
			res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
			res.end(JSON.stringify(value));
		};
		if (req.url === "/.well-known/oauth-authorization-server")
			return json(200, {
				issuer: origin,
				token_endpoint: `${origin}/token`,
				grant_types_supported: [exchangeGrant],
			});
		if (req.url !== "/token" || req.method !== "POST") return json(404, {});
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			const form = new URLSearchParams(Buffer.concat(chunks).toString());
			if (
				form.get("grant_type") !== exchangeGrant ||
				form.get("requested_token_type") !== idJagType
			)
				return json(400, { error: "unsupported_grant_type" });
			const basic = req.headers.authorization?.startsWith("Basic ")
				? Buffer.from(req.headers.authorization.slice(6), "base64").toString().split(":")[0]
				: undefined;
			const client = form.get("client_id") ?? (basic ? decodeURIComponent(basic) : "");
			const jkt = proofKey(req.headers.dpop as string | undefined);
			const told = next;
			next = {};
			const now = Math.floor(Date.now() / 1000);
			const head = b64({ alg: "ES256", typ: told.typ ?? "oauth-id-jag+jwt" });
			const claims = {
				iss: origin,
				sub: "alice",
				aud: told.aud ?? form.get("audience"),
				client_id: told.clientId ?? client,
				jti: randomBytes(16).toString("base64url"),
				iat: now,
				exp: now + 300,
				...(form.get("scope") ? { scope: form.get("scope") } : {}),
				...(jkt ? { cnf: { jkt } } : {}),
			};
			issued.push(claims);
			const body = b64(claims);
			const signature = sign("sha256", Buffer.from(`${head}.${body}`), {
				key: key.privateKey,
				dsaEncoding: "ieee-p1363",
			}).toString("base64url");
			json(200, {
				access_token: `${head}.${body}.${signature}`,
				issued_token_type: idJagType,
				token_type: "N_A",
				expires_in: 300,
			});
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	origin = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
	return {
		issuer: origin,
		ca: tls.cert,
		publicPem: key.publicKey.export({ format: "pem", type: "spki" }).toString(),
		otherwise: (told) => {
			next = told;
		},
		issued: () => [...issued],
		stop: () => new Promise((resolve) => server.close(() => resolve())),
	};
}
