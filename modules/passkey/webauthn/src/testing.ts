import { createHash, generateKeyPairSync, type KeyObject, randomBytes, sign } from "node:crypto";
import type { z } from "zod";
import type { section } from "./section.ts";

export type WebauthnSettings = z.input<typeof section>;

export const testOrigin = "https://rp.example";

/** The ceremonies over a relying party, randomness and a clock a test gives, as the module builds them. */
export { ceremoniesFor as testCeremonies } from "./ceremony/ceremony.ts";

/** The webauthn part of a test's configuration: a relying party at `rp.example`. */
export function webauthnConfig(settings: Partial<WebauthnSettings> = {}) {
	return {
		webauthn: { "rp-id": "rp.example", "rp-name": "RP", origins: [testOrigin], ...settings },
	};
}

/** Where a ceremony runs, as the browser reports it in the client data. */
export interface Client {
	readonly origin: string;
	readonly crossOrigin?: boolean;
	readonly topOrigin?: string;
}

/** What an authenticator may be told to do otherwise, for a test of a refusal. */
export interface Twist {
	/** The relying party the authenticator data names, instead of the one the options name. */
	readonly rpId?: string;
	/** The user handle an assertion carries; null carries none. */
	readonly userHandle?: string | null;
	/** The count an assertion carries. */
	readonly counter?: number;
	/** The id a new credential takes, instead of 16 random bytes. */
	readonly credentialId?: string;
	/** The client data, encoded as given instead of as JSON in base64url. */
	readonly clientDataJSON?: (json: string) => string;
	/** Answers what a browser would refuse: the options' rules and its own limits are not checked. */
	readonly overlook?: boolean;
}

/** Credential creation options, as a relying party sends them in JSON. */
export interface CreationOptions {
	readonly rp: { readonly id?: string };
	readonly user: { readonly id: string };
	readonly challenge: string;
	readonly pubKeyCredParams: readonly { readonly alg: number; readonly type: string }[];
	readonly excludeCredentials?: readonly { readonly id: string; readonly type: string }[];
	readonly authenticatorSelection?: {
		readonly residentKey?: string;
		readonly requireResidentKey?: boolean;
		readonly userVerification?: string;
	};
}

/** Credential request options, as a relying party sends them in JSON. */
export interface RequestOptions {
	readonly challenge: string;
	readonly rpId?: string;
	readonly allowCredentials?: readonly { readonly id: string; readonly type: string }[];
	readonly userVerification?: string;
}

type Cbor = number | string | Uint8Array | Map<Cbor, Cbor>;

/** CBOR for the few kinds WebAuthn uses: integers, text, bytes and maps. */
function cbor(value: Cbor): number[] {
	const head = (major: number, n: number) =>
		n < 24
			? [(major << 5) | n]
			: n < 256
				? [(major << 5) | 24, n]
				: [(major << 5) | 25, n >> 8, n & 255];
	if (typeof value === "number") return value >= 0 ? head(0, value) : head(1, -1 - value);
	if (typeof value === "string") {
		const bytes = Buffer.from(value);
		return [...head(3, bytes.length), ...bytes];
	}
	if (value instanceof Uint8Array) return [...head(2, value.length), ...value];
	return [...head(5, value.size), ...[...value].flatMap(([k, v]) => [...cbor(k), ...cbor(v)])];
}

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64url");

/** Authenticator data flags: user present, user verified, backup eligible, backed up, attested data. */
const [UP, UV, BE, BS, AT] = [1, 4, 8, 16, 64];

/** A browser's refusal, named as `navigator.credentials` names it. */
const refused = (name: string, message: string) => new DOMException(message, name);

/** Whether a browser on `host` takes `rpId`: the host, or a domain above it but no single label. */
const servesHost = (rpId: string, host: string) =>
	host === rpId || (host.endsWith(`.${rpId}`) && rpId.includes("."));

interface Kept {
	readonly key: KeyObject;
	readonly handle: string;
	readonly rpId: string;
	readonly discoverable: boolean;
	count: number;
}

/**
 * A software WebAuthn authenticator behind a browser: it makes ES256 (or ES384) credentials,
 * attests with `none`, asserts with a count that goes up unless it keeps none, and checks the
 * options as a browser does unless a twist says to overlook them.
 */
export function softwareAuthenticator(
	settings: {
		/** Whether it can verify the user; it can unless told otherwise. */
		readonly userVerified?: boolean;
		readonly backupEligible?: boolean;
		readonly countless?: boolean;
		readonly algorithm?: "ES256" | "ES384";
		/** Whether it can keep a discoverable credential; it can unless told otherwise. */
		readonly discoverable?: boolean;
	} = {},
) {
	const kept = new Map<string, Kept>();
	const alg = settings.algorithm === "ES384" ? -35 : -7;
	const canVerify = settings.userVerified !== false;
	const canDiscover = settings.discoverable !== false;
	const flags = (attested: boolean, verified: boolean) =>
		UP | (verified ? UV : 0) | (settings.backupEligible ? BE | BS : 0) | (attested ? AT : 0);
	/** Verifies the user unless told it is discouraged, and only when it can; required and unable is refused. */
	const verifies = (asked: string | undefined, twist: Twist) => {
		check(twist, asked === "required" && !canVerify, "NotAllowedError", "cannot verify the user");
		return canVerify && asked !== "discouraged";
	};
	const authData = (
		rp: string,
		attested: boolean,
		verified: boolean,
		count: number,
		rest: number[] = [],
	) => {
		const counter = Buffer.alloc(4);
		counter.writeUInt32BE(count);
		const rpHash = createHash("sha256").update(rp).digest();
		return Buffer.from([...rpHash, flags(attested, verified), ...counter, ...rest]);
	};
	const clientData = (type: string, challenge: string, client: Client, twist: Twist) => {
		// A browser names a top origin only for a page in a cross-origin frame.
		if (client.topOrigin !== undefined && client.crossOrigin !== true && !twist.overlook) {
			throw new Error("a top origin is reported only in a cross-origin frame");
		}
		const json = JSON.stringify({
			type,
			challenge,
			origin: client.origin,
			crossOrigin: client.crossOrigin ?? false,
			...(client.topOrigin ? { topOrigin: client.topOrigin } : {}),
		});
		return twist.clientDataJSON ? twist.clientDataJSON(json) : b64(json);
	};
	/** The relying party a browser on the client's page takes, or its refusal. */
	const rpFor = (asked: string | undefined, client: Client, twist: Twist) => {
		const host = new URL(client.origin).hostname;
		const rpId = asked ?? host;
		if (!twist.overlook && !servesHost(rpId, host)) {
			throw refused("SecurityError", `${rpId} is not a domain of ${host}`);
		}
		return rpId;
	};
	/** Throws the refusal a browser answers where `broken`, unless told to overlook it. */
	const check = (twist: Twist, broken: boolean, name: string, message: string) => {
		if (broken && !twist.overlook) throw refused(name, message);
	};

	const create = (options: CreationOptions, client: Client, twist: Twist = {}) => {
		const rpId = rpFor(options.rp.id, client, twist);
		const clientDataJSON = clientData("webauthn.create", options.challenge, client, twist);
		const handleBytes = Buffer.from(options.user.id, "base64url").length;
		check(twist, handleBytes < 1 || handleBytes > 64, "TypeError", "user.id is 1 to 64 bytes");
		const offered = options.pubKeyCredParams.some((p) => p.type === "public-key" && p.alg === alg);
		check(twist, !offered, "NotSupportedError", "no algorithm it has is offered");
		const excluded = (options.excludeCredentials ?? []).some((c) => kept.get(c.id)?.rpId === rpId);
		check(twist, excluded, "InvalidStateError", "it holds an excluded credential");
		const selection = options.authenticatorSelection ?? {};
		const residentKey =
			selection.residentKey ?? (selection.requireResidentKey ? "required" : "discouraged");
		check(twist, residentKey === "required" && !canDiscover, "NotAllowedError", "not discoverable");
		const verified = verifies(selection.userVerification, twist);

		const { privateKey, publicKey } = generateKeyPairSync("ec", {
			namedCurve: alg === -35 ? "P-384" : "P-256",
		});
		const jwk = publicKey.export({ format: "jwk" });
		const cose = new Map<Cbor, Cbor>([
			[1, 2],
			[3, alg],
			[-1, alg === -35 ? 2 : 1],
			[-2, Buffer.from(jwk.x ?? "", "base64url")],
			[-3, Buffer.from(jwk.y ?? "", "base64url")],
		]);
		const id = twist.credentialId ? Buffer.from(twist.credentialId, "base64url") : randomBytes(16);
		const attested = [...Buffer.alloc(16), id.length >> 8, id.length & 255, ...id, ...cbor(cose)];
		const data = authData(twist.rpId ?? rpId, true, verified, 0, attested);
		const discoverable = canDiscover && residentKey !== "discouraged";
		kept.set(b64(id), { key: privateKey, handle: options.user.id, rpId, discoverable, count: 0 });
		const attestationObject = cbor(
			new Map<Cbor, Cbor>([
				["fmt", "none"],
				["attStmt", new Map()],
				["authData", data],
			]),
		);
		return {
			id: b64(id),
			rawId: b64(id),
			type: "public-key",
			response: {
				clientDataJSON,
				attestationObject: b64(Buffer.from(attestationObject)),
				transports: ["internal"],
			},
			clientExtensionResults: {},
		};
	};

	const get = (options: RequestOptions, client: Client, twist: Twist = {}, pick?: string) => {
		const rpId = rpFor(options.rpId, client, twist);
		const clientDataJSON = clientData("webauthn.get", options.challenge, client, twist);
		const listed = (options.allowCredentials ?? []).map((c) => c.id);
		// With none listed, a browser offers the discoverable credentials it holds for the party.
		const offered = [...kept].filter(([id, c]) =>
			twist.overlook
				? true
				: c.rpId === rpId && (listed.length ? listed.includes(id) : c.discoverable),
		);
		const chosen = offered.find(([id]) => id === pick) ?? (pick ? undefined : offered.at(-1));
		if (!chosen) throw refused("NotAllowedError", "no credential it holds is asked for");
		const verified = verifies(options.userVerification, twist);
		const [id, credential] = chosen;
		if (!settings.countless) credential.count += 1;
		const count = twist.counter ?? credential.count;
		const data = authData(twist.rpId ?? credential.rpId, false, verified, count);
		const signed = Buffer.concat([
			data,
			createHash("sha256").update(Buffer.from(clientDataJSON, "base64url")).digest(),
		]);
		// An authenticator answers the handle only of a credential it keeps discoverable.
		const own = credential.discoverable ? credential.handle : null;
		const handle = twist.userHandle === undefined ? own : twist.userHandle;
		return {
			id,
			rawId: id,
			type: "public-key",
			response: {
				clientDataJSON,
				authenticatorData: b64(data),
				signature: b64(sign(alg === -35 ? "sha384" : "sha256", signed, credential.key)),
				...(handle === null ? {} : { userHandle: handle }),
			},
			clientExtensionResults: {},
		};
	};

	return {
		/** Answers creation options as `navigator.credentials.create` does. */
		create,
		/** Answers request options as `navigator.credentials.get` does, with `pick` if the user picks one. */
		get,
	};
}
