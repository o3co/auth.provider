/** Trial settings for a generated app: values that boot it for a test or a conformance run, never for a deployment. */
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { envName } from "./fragments.ts";
import { auditReceiversOf } from "./patterns/chosen.ts";

/** Every key an app may read from its variable, by section, with a trial value; one the app does not read is left unread. */
function trialValues(redisUrl: string): [section: string, key: string, value: string][] {
	const { privateKey } = generateKeyPairSync("ed25519");
	return [
		["issuer", "url", "https://login.example.invalid"],
		["keys", "signing.kid", "signing-1"],
		["keys", "signing.alg", "EdDSA"],
		["keys", "signing.private-key", privateKey.export({ type: "pkcs8", format: "pem" }).toString()],
		["tokens", "revocation", "denylist"],
		["audit-http", "url", "https://audit.example.invalid/events"],
		["redis", "url", redisUrl],
		["redis", "replication", "none"],
		["store", "accept-volatile", "true"],
		["mail", "accept-unsent", "true"],
		["device-grant", "verification-uri", "https://login.example.invalid/device"],
		["mtls", "mode", "self-signed"],
		["mail-smtp", "host", "smtp.example.invalid"],
		["mail-smtp", "from", "auth@example.invalid"],
	];
}

/** The trial's own client that exchanges id_tokens, where exchange-id-tokens is composed: it needs one registered. */
const idTokenClient = { id: "trial-id-tokens", kind: "public", method: "none", sections: {} };

/** The local layer's blocks, by section: each kept where the app composes the module it is for. */
function trialBlocks(
	modules: readonly string[],
	deployment: string,
	port: number | undefined,
	added: {
		readonly allow: readonly string[];
		readonly plainLoopback: readonly string[];
		readonly clients: readonly unknown[];
	},
) {
	const has = (name: string) => modules.includes(name);
	const hosts = [
		...(has("users-http") || has("signer-keys-http") ? ["ledger.example.invalid"] : []),
		...(has("audit-http") ? ["audit.example.invalid"] : []),
		...added.allow,
	];
	const loopback =
		added.plainLoopback.length > 0
			? `, plain-loopback = [${added.plainLoopback.map((h) => JSON.stringify(h)).join(", ")}]`
			: "";
	const receivers = auditReceiversOf((module) => has(module.slice("@mod/".length)));
	const clients = [...added.clients, ...(has("exchange-id-tokens") ? [idTokenClient] : [])];
	const blocks: [boolean, string, string][] = [
		[true, "kernel", `kernel { deployment = ${deployment} }`],
		[true, "audit", `audit { receivers = [${receivers.join(", ")}] }`],
		[
			has("authorize"),
			"authorize",
			`authorize { login-page = "https://login.example.invalid/login" }`,
		],
		[
			has("users-http"),
			"users-http",
			`users-http { verify-url = "https://ledger.example.invalid/verify", subject-url = "https://ledger.example.invalid/subject" }`,
		],
		[
			has("signer-keys-http"),
			"signer-keys-http",
			`signer-keys-http { issuer = "https://devices.example.invalid", keys-url = "https://ledger.example.invalid/signer-keys" }`,
		],
		// jwt-bearer refuses keys contributed for an issuer it does not name; signer-keys-http contributes these.
		[
			has("jwt-bearer") && has("signer-keys-http"),
			"jwt-bearer",
			`jwt-bearer { issuers = [{ issuer = "https://devices.example.invalid", subject = as-is }] }`,
		],
		[
			has("http"),
			"http",
			`http { public-origin = "https://login.example.invalid"${port ? `, port = ${port}` : ""} }`,
		],
		[has("mtls"), "http", `http { client-certificate { dialect = pem, header = x-client-cert } }`],
		[
			has("outbound") && (hosts.length > 0 || loopback !== ""),
			"outbound",
			`outbound { allow = [${hosts.join(", ")}]${loopback} }`,
		],
		// The trial's alone: a scene that proves no factor would stop at enrolment under required.
		[has("mfa"), "mfa", "mfa { mode = optional }"],
		// The relying party is the trial's public origin, where passkeys are composed.
		[
			has("webauthn"),
			"webauthn",
			'webauthn { rp-id = login.example.invalid, rp-name = "Trial", origins = ["https://login.example.invalid"] }',
		],
		// Lists replace each other across layers, so the caller's clients join the trial's one list.
		[
			has("clients") && clients.length > 0,
			"clients",
			`clients { registered = ${JSON.stringify(clients)} }`,
		],
		[
			has("exchange-id-tokens"),
			"exchange-id-tokens",
			`exchange-id-tokens { google { clients { ${idTokenClient.id} { audiences = ["trial-google-server-client-id"] } } } }`,
		],
		[
			has("seal"),
			"seal",
			`seal { current { id = seal-1, key = "${randomBytes(32).toString("base64")}" } }`,
		],
	];
	return blocks.flatMap(([kept, section, block]) => (kept ? [{ section, block }] : []));
}

/**
 * Trial settings for the app generated in `target`, by the modules its entry imports: the
 * environment, and a local layer to put before the generated configuration. Keys are made fresh.
 * The sections in `leave` get neither a variable nor a block, so the caller's own layer decides them.
 */
export async function trialSettings(
	target: string,
	settings: {
		readonly redisUrl: string;
		readonly port?: number;
		readonly deployment?: "single" | "multi";
		readonly leave?: readonly string[];
		/** Hosts the caller's own layer needs reached, merged into the trial's one outbound block. */
		readonly allow?: readonly string[];
		readonly plainLoopback?: readonly string[];
		/** Clients the caller's own layer registers, merged into the trial's one `clients.registered`. */
		readonly clients?: readonly unknown[];
	},
): Promise<{ readonly env: Record<string, string>; readonly local: string }> {
	// The modules the entry imports, by their directory's name, as the workspace or a bundle names them.
	const entry = await readFile(join(target, "src", "main.ts"), "utf8");
	const modules = [...entry.matchAll(/from "(?:[^"]*\/)?([a-z0-9-]+)\/module"/g)].map(
		(found) => found[1] as string,
	);
	const kept = (section: string) => !(settings.leave ?? []).includes(section);
	const env = Object.fromEntries(
		trialValues(settings.redisUrl)
			.filter(([section]) => kept(section))
			.map(([section, key, value]) => [envName(`${section}.${key}`), value]),
	);
	const added = {
		allow: settings.allow ?? [],
		plainLoopback: settings.plainLoopback ?? [],
		clients: settings.clients ?? [],
	};
	const blocks = trialBlocks(modules, settings.deployment ?? "single", settings.port, added).filter(
		(b) => kept(b.section),
	);
	return { env, local: `${blocks.map((b) => b.block).join("\n")}\n` };
}
