import { join } from "node:path";
import { readChecklist } from "@mod/spec-checklist";
import { afterAll, beforeAll, describe, expect, it, type TestContext } from "vitest";
import { converse } from "../src/dialog/dialog.ts";
import { differencesOf, readDifferences } from "../src/differences/differences.ts";
import { type Flow, libraries, libraryNamed } from "../src/libraries/libraries.ts";
import { startWorld, type World, type WorldClient } from "./world/world.ts";

const library = libraryNamed(process.env.INTEROP_LIBRARY);
const runs = (flow: Flow) => library.flows.includes(flow);
const checklist = readChecklist();
const differences = differencesOf(
	readDifferences(
		join(import.meta.dirname, "..", "known-differences.json"),
		{
			items: new Map(checklist.specs.flatMap((s) => s.items.map((i) => [i.id, i] as const))),
			decisions: checklist.decisions,
		},
		libraries.map((l) => l.name),
	),
	library.name,
);

/** Runs a check; a failure a known difference names is skipped as excused, by its class. */
async function excusable(context: TestContext, flow: Flow, check: () => Promise<void>) {
	try {
		await check();
	} catch (failure) {
		const known = differences.excusing(flow, context.task.name);
		if (!known) throw failure;
		context.skip(`excused: ${known.class}`);
	}
}

let world: World;
beforeAll(async () => {
	world = await startWorld();
});
afterAll(async () => {
	await world?.stop();
});

/** Runs one flow with the library, answering its browser steps; a flow that gives no result fails. */
async function run(flow: Flow, client: WorldClient, extra: Record<string, unknown> = {}) {
	const browser = world.browser();
	const dialog = await converse(
		library.adapter(),
		{ flow, issuer: world.issuer, ca: world.ca, client, redirectUri: world.redirectUri, ...extra },
		async (ask) => {
			if (ask.ask === "browse") return { location: await browser.authorize(String(ask.url)) };
			throw new Error(`the driver has no answer to ${ask.ask}`);
		},
		90_000,
	);
	if (dialog.outcome.kind !== "result")
		throw new Error(
			`${library.name} ${flow}: ${dialog.outcome.type}: ${dialog.outcome.message}\n${dialog.stderr.slice(-2000)}`,
		);
	return dialog.outcome.result as Record<string, unknown>;
}

const claims = (value: unknown) => value as Record<string, unknown>;

describe(`${library.name}: signing in`, () => {
	it.runIf(runs("login"))(
		"signs in by the code flow with PKCE and client_secret_basic, the ID token checked and userinfo read",
		(context) =>
			excusable(context, "login", async () => {
				const result = await run("login", world.clients.basic, { scope: "openid profile email" });
				const id = claims(result.idToken);
				expect(id.iss).toBe(world.issuer);
				expect([id.aud].flat()).toContain(world.clients.basic.id);
				expect(claims(result.userinfo).sub).toBe(id.sub);
				expect(String(result.tokenType).toLowerCase()).toBe("bearer");
			}),
	);

	it.runIf(runs("login"))("signs in with client_secret_post", (context) =>
		excusable(context, "login", async () => {
			const result = await run("login", world.clients.post);
			expect(claims(result.idToken).iss).toBe(world.issuer);
		}),
	);

	it.runIf(runs("public-login"))("signs in a public client, by PKCE alone", (context) =>
		excusable(context, "public-login", async () => {
			const result = await run("public-login", world.clients.public);
			const id = claims(result.idToken);
			expect([id.aud].flat()).toContain(world.clients.public.id);
			expect(claims(result.userinfo).sub).toBe(id.sub);
		}),
	);
});

describe(`${library.name}: refreshing`, () => {
	it.runIf(runs("refresh"))(
		"refreshes the access token, the refresh token rotated and the one it replaced refused",
		(context) =>
			excusable(context, "refresh", async () => {
				const result = await run("refresh", world.clients.basic);
				expect(result).toEqual({ accessToken: true, rotated: true, replayed: "invalid_grant" });
			}),
	);
});

describe(`${library.name}: the known differences`, () => {
	it("are each met by a check of this run, so a fixed one is taken out", () => {
		expect(differences.unmet()).toEqual([]);
	});
});
