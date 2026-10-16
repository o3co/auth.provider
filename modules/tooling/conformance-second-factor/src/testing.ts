import { createHmac } from "node:crypto";
import {
	type AreaScene,
	areaTarget,
	auditEvents,
	type Mailbox,
	type Started,
} from "@mod/conformance";
import { afterAll, beforeAll, expect } from "vitest";

/** The issuer and the one password the second-factor scenes give their users. */
export const issuer = "https://issuer.example";
export const password = "correct horse battery";

/** RFC 6238 (SHA-1, 6 digits, 30 s): the code for the step `offset` steps from now. */
export function totp(secret: string, offset = 0): string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	let bits = 0;
	let value = 0;
	const key: number[] = [];
	for (const char of secret.replace(/=+$/, "")) {
		value = (value << 5) | alphabet.indexOf(char);
		bits += 5;
		if (bits >= 8) {
			key.push((value >>> (bits - 8)) & 255);
			bits -= 8;
		}
	}
	const counter = Buffer.alloc(8);
	counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000) + offset));
	const mac = createHmac("sha1", Buffer.from(key)).update(counter).digest();
	const at = (mac[mac.length - 1] ?? 0) & 15;
	return String((mac.readUInt32BE(at) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

/** A browser behind the deployment's proxy: it keeps its cookies and sends the double-submit token. */
export function browser(base: () => string) {
	const jar = new Map<string, string>();
	let csrf = "";
	const keep = (set: string[]) => {
		for (const c of set) {
			const [first = ""] = c.split(";");
			const at = first.indexOf("=");
			const [name, value] = [first.slice(0, at), first.slice(at + 1)];
			if (value) jar.set(name, value);
			else jar.delete(name);
		}
	};
	const headers = (extra: Record<string, string> = {}) => ({
		"x-forwarded-proto": "https",
		"x-forwarded-for": "198.51.100.30",
		"x-forwarded-host": new URL(issuer).host,
		origin: issuer,
		cookie: [...jar].map(([k, v]) => `${k}=${v}`).join("; "),
		...extra,
	});
	/** A POST sends a form unless asked to send JSON; answers the headers too. */
	const exchange = async (
		method: "GET" | "POST",
		path: string,
		form: Record<string, unknown> = {},
		extra = {},
		as: "form" | "json" = "form",
	) => {
		if (method === "POST" && !csrf) {
			const issued = await fetch(`${base()}/session/csrf`, { headers: headers() });
			keep(issued.headers.getSetCookie());
			csrf = ((await issued.json()) as { csrf_token: string }).csrf_token;
		}
		const res = await fetch(`${base()}${path}`, {
			method,
			redirect: "manual",
			headers: headers({
				...(method === "POST"
					? {
							"content-type":
								as === "json" ? "application/json" : "application/x-www-form-urlencoded",
							"x-csrf-token": csrf,
						}
					: {}),
				...extra,
			}),
			...(method === "POST"
				? {
						body:
							as === "json"
								? JSON.stringify(form)
								: new URLSearchParams(form as Record<string, string>),
					}
				: {}),
		});
		keep(res.headers.getSetCookie());
		const text = await res.text();
		return {
			status: res.status,
			headers: res.headers,
			body: (text ? JSON.parse(text) : {}) as Record<string, unknown>,
		};
	};
	/** A POST sends a form unless asked to send JSON. */
	const send = async (...asked: Parameters<typeof exchange>) => {
		const { status, body } = await exchange(...asked);
		return { status, body };
	};
	return {
		jar,
		send,
		exchange,
		login: (username: string, extra: Record<string, string> = {}) =>
			send("POST", "/session/login", { username, password, ...extra }),
		factors: async (transaction: string) =>
			(await send("GET", "/session/mfa/transaction", {}, { "mfa-transaction": transaction })).body
				.factors as { id: string; kind: string }[],
	};
}
export const sessionCookie = (jar: Map<string, string>) =>
	[...jar].find(([name]) => /session/.test(name) && !/csrf|mfa/.test(name))?.[1];

/** A target started with the scene, or with the one built once the hooks registered before have run. */
export function running(scene: AreaScene | (() => AreaScene)) {
	let started: Started;
	const at = { base: "" };
	beforeAll(async () => {
		started = await areaTarget().start(typeof scene === "function" ? scene() : scene);
		if (started.kind !== "running") throw new Error(`refused:\n${started.output}`);
		at.base = started.baseUrl;
	});
	afterAll(async () => {
		if (started?.kind === "running") await started.stop();
	});
	/** Signs a user in and binds TOTP; answers the TOTP secret, the recovery codes and whether a binding proof was sent. */
	const enrol = async (username: string) => {
		const b = browser(() => at.base);
		expect((await b.login(username)).status).toBe(200);
		const begun = await beginBinding(b, { kind: "totp" }, mail());
		const secret = String(begun.body.secret);
		const done = await b.send("POST", "/session/mfa/enrollment/complete", {
			transaction_id: String(begun.body.transaction),
			proof: totp(secret),
		});
		expect(done.status).toBe(200);
		return { secret, codes: done.body.recovery_codes as string[], proved: begun.proved };
	};
	/** A fresh browser whose password login a second factor holds. */
	const held = async (username: string, extra: Record<string, string> = {}) => {
		const b = browser(() => at.base);
		const answer = await b.login(username, extra);
		return { b, answer, transaction: String(answer.body.transaction) };
	};
	/** The audit events the running target sends; only for a scene that states the need. */
	const trail = () => auditEvents.of(started);
	/** The mail the target sent, where the driver runs its relay. */
	const mail = () => (started?.kind === "running" ? started.mail : undefined);
	return { at, enrol, held, trail, mail };
}

type Browser = ReturnType<typeof browser>;

/** The acr a second factor meets, as clients ask for it. */
export const secondFactorAcr = "urn:o3co:acr:mfa";

/**
 * Begins binding a factor, as a user would: where the target asks a binding proof first, it sends the
 * code mailed to the user. Answers whether it did, as `proved`.
 */
export async function beginBinding(
	b: Browser,
	form: Record<string, unknown>,
	mail: Mailbox | undefined,
	as: "form" | "json" = "form",
) {
	const before = mail?.received.length ?? 0;
	const begun = await b.send("POST", "/session/mfa/enrollment", form, {}, as);
	if (begun.body.error !== "mfa_binding_proof_required" || !mail)
		return { ...begun, proved: false };
	const code = /\b([0-9A-Z]{16})\b/.exec(mail.received.slice(before).at(-1)?.text ?? "")?.[1];
	const proof = { ...form, transaction_id: String(begun.body.transaction), proof: code ?? "" };
	return { ...(await b.send("POST", "/session/mfa/enrollment", proof, {}, as)), proved: true };
}

/** Lets a held login in with a recovery code, so the next TOTP step stays free for a step-up. */
export async function letInByRecovery(b: Browser, transaction: string, code: string) {
	const way = (await b.factors(transaction)).find((f) => f.kind !== "totp");
	return b.send("POST", "/session/mfa/verify", {
		transaction_id: transaction,
		factor_id: way?.id ?? "",
		proof: code,
	});
}

/** Raises the browser's session by a step-up proved with the TOTP code one step ahead. */
export async function stepUp(b: Browser, secret: string) {
	const step = await b.send("POST", "/session/mfa/step-up");
	const transaction = String(step.body.transaction);
	const factor = (await b.factors(transaction)).find((f) => f.kind === "totp");
	return b.send("POST", "/session/mfa/verify", {
		transaction_id: transaction,
		factor_id: factor?.id ?? "",
		proof: totp(secret, 1),
	});
}
