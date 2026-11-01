import { generateKeyPairSync } from "node:crypto";
import { type AreaScene, sceneOf } from "@mod/conformance";
import {
	type Deployed,
	type Deploying,
	type Instance,
	on as onDeployment,
} from "@mod/conformance/testing";
import { identityArea, type RevocationScene } from "@mod/conformance-identity";
import { keysArea } from "@mod/conformance-keys";
import { expect } from "vitest";
// The package's entry, which sets the area up on each target.
import { secondFactorArea } from "../../main.ts";
import { beginBinding, browser, issuer, letInByRecovery, password, totp } from "../../testing.ts";

const pair = generateKeyPairSync("ed25519");
const user = "alice";

/** A password login a second factor holds, on the Redis store, for one user, the ledger revoking subjects where a scene says. */
export const faultScene = (revocations?: RevocationScene): AreaScene => ({
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
			users: [{ identifier: user, password }],
			// A scene's value, not the default: a scene logs the user in a dozen times in one window.
			login: { attempts: 100, windowSeconds: 600 },
			...(revocations ? { revocations } : {}),
		}),
		secondFactorArea.part({ mode: "optional" }),
	),
	storeFaults: true,
});

/** Runs a scene on a deployment of its own, as the base does, on the second factor's scene unless it names another. */
export const on = (
	o: Omit<Deploying, "scene"> & { readonly scene?: AreaScene },
	scene: (d: Deployed) => Promise<void>,
) => onDeployment({ ...o, scene: o.scene ?? faultScene() }, scene);

export type Browser = ReturnType<typeof browser>;

/** An answer as a scene compares it: its status and error. */
export const said = (a: { status: number; body: Record<string, unknown> }) => [
	a.status,
	a.body.error,
];

/** The user's recovery codes, each given to a scene once. */
export interface Codes {
	next(): string;
}

/** Binds TOTP for the user at the instance; answers the recovery codes it gave. */
export async function enrolledAt(i: Instance): Promise<Codes> {
	const b = browser(() => i.baseUrl);
	expect((await b.login(user)).status).toBe(200);
	const begun = await beginBinding(b, { kind: "totp" }, undefined);
	const done = await b.send("POST", "/session/mfa/enrollment/complete", {
		transaction_id: String(begun.body.transaction),
		proof: totp(String(begun.body.secret)),
	});
	expect(done.status).toBe(200);
	const codes = [...(done.body.recovery_codes as string[])];
	return {
		next() {
			const code = codes.shift();
			if (!code) throw new Error("no recovery code left");
			return code;
		},
	};
}

/** A login at the instance that the second factor holds: its browser and transaction. */
export async function heldAt(i: Instance): Promise<{ b: Browser; transaction: string }> {
	const b = browser(() => i.baseUrl);
	const answer = await b.login(user);
	expect(said(answer)).toEqual([403, "mfa_required"]);
	return { b, transaction: String(answer.body.transaction) };
}

/** The same browser, its cookies and all, behind another instance. */
export function movedTo(i: Instance, b: Browser): Browser {
	const moved = browser(() => i.baseUrl);
	for (const [name, value] of b.jar) moved.jar.set(name, value);
	return moved;
}

/** The held login let in, or not, by the recovery code. */
export const usedAt = (b: Browser, transaction: string, code: string) =>
	letInByRecovery(b, transaction, code);
