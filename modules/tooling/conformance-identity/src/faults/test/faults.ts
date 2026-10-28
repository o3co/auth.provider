import { generateKeyPairSync } from "node:crypto";
import { type AreaScene, sceneOf } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import { keysArea } from "@mod/conformance-keys";
// The package's entry, which sets the area up on each target.
import { type IdentityPart, identityArea } from "../../main.ts";

export const issuer = "https://issuer.example";
const pair = generateKeyPairSync("ed25519");
export const alice = { username: "alice", password: "alice-horse-battery-staple" };

/** Password login on the Redis store, for one user, with what a scene adds. */
export const faultScene = (more: Partial<IdentityPart> = {}): AreaScene => ({
	...sceneOf(
		keysArea.part({
			signing: {
				kid: "faults",
				alg: "EdDSA",
				privatePem: pair.privateKey.export({ format: "pem", type: "pkcs8" }).toString(),
				publicPem: pair.publicKey.export({ format: "pem", type: "spki" }).toString(),
			},
		}),
		identityArea.part({
			origin: issuer,
			users: [{ identifier: alice.username, password: alice.password }],
			...more,
		}),
	),
	storeFaults: true,
});

/** Runs a scene on a deployment of its own, as the base does, on password login's scene unless it names another. */
export const on = (
	o: Omit<Deploying, "scene"> & { readonly scene?: AreaScene },
	scene: (d: Deployed) => Promise<void>,
) => onDeployment({ ...o, scene: o.scene ?? faultScene() }, scene);

let sent = 0;
/** A source of its own, as the proxy forwards it, so no scene's count takes another's. */
export const nextSource = () => `198.51.100.${++sent}`;

/** A login's answer: its status, its error, the session cookie it set, the wait it asks, and when it came. */
export interface Answer {
	readonly status: number;
	readonly error?: string;
	readonly session?: string;
	/** `retry-after`, in seconds, where the answer asks a wait. */
	readonly retryAfter?: number;
	readonly at: number;
}

/** A password login at the instance, as its proxy forwards it from `source`. */
export async function loginAt(
	i: Instance,
	source: string,
	credentials: { username: string; password: string } = alice,
): Promise<Answer> {
	const res = await fetch(`${i.baseUrl}/session/login`, {
		method: "POST",
		headers: {
			"content-type": "application/x-www-form-urlencoded",
			"x-forwarded-proto": "https",
			"x-forwarded-for": source,
			"x-forwarded-host": new URL(issuer).host,
			origin: issuer,
		},
		body: new URLSearchParams(credentials),
		redirect: "manual",
	});
	const text = await res.text();
	let body: Record<string, unknown> = {};
	try {
		body = text ? (JSON.parse(text) as Record<string, unknown>) : {};
	} catch {}
	const session = res.headers
		.getSetCookie()
		.map((c) => c.split(";")[0] ?? "")
		.find((c) => /^__Host-[^=]*session=/.test(c) && !/csrf/.test(c));
	const wait = res.headers.get("retry-after");
	return {
		status: res.status,
		...(typeof body.error === "string" ? { error: body.error } : {}),
		...(session ? { session } : {}),
		...(wait === null ? {} : { retryAfter: Number(wait) }),
		at: performance.now(),
	};
}

/** An answer as a scene compares it: its status and error, and whether it opened a session. */
export const said = (a: Answer) => [a.status, a.error, a.session !== undefined];
