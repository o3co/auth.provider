import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import {
	assemble,
	BootRefused,
	contract,
	defineModule,
	isUnavailable,
	kernelConfig,
	type Module,
	Unavailable,
} from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { type Factors, factors } from "@mod/mfa";
import { type FactorKind, factorKinds, secondFactorAmr } from "@mod/mfa-extensions";
import { type EntryRequirement, entryRequirements, sessionRules, sessions } from "@mod/session";
import { sessionStandIn } from "@mod/session/testing";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { afterEach, describe, expect, it } from "vitest";
import { secondFactors } from "../src/contract.ts";
import entry from "../src/module.ts";

let shift = 0;
/** Where set, the clock stands at this time (before the shift), so a test can judge a window's very edge. */
let stopped: number | undefined;
/** `session`'s recent-authentication window, as its stand-in counts it. */
const recentMs = sessionRules.credentialsSecondsDefault * 1000;
const runtime = quietRuntime({ clock: { now: () => (stopped ?? Date.now()) + shift } });
afterEach(() => {
	shift = 0;
	stopped = undefined;
});

const kind = (counts: boolean, addsSecondFactor: boolean) =>
	({ kind: "k", amr: ["otp"], counts, addsSecondFactor }) as unknown as FactorKind;

/** mfa's decisions as the entry judgments ask them: the subjects holding a counting factor, or one unreadable. */
function decided(holding: Set<string>, required = false, unreadable = new Set<string>()) {
	const asked: string[] = [];
	const module = defineModule({ name: "factors-stand-in" }, (m) => [
		m.provide(factors).by(
			() =>
				({
					countingHeld: async (subject: string, at: string) => {
						asked.push(`${subject} ${at}`);
						if (unreadable.has(subject)) throw new Unavailable("mfa");
						return holding.has(subject);
					},
					secondFactorRequired: () => required,
				}) as unknown as Factors,
		),
	]);
	return { module, asked };
}

async function serve(
	holding = new Set<string>(),
	{ required = false, unreadable = new Set<string>(), kinds = [kind(true, true)] } = {},
	extra: Module[] = [],
) {
	const stand = decided(holding, required, unreadable);
	const kindsModule = defineModule({ name: "kinds" }, (m) =>
		kinds.map((k) => m.contribute(factorKinds).by(() => k)),
	);
	const app = await assemble({
		modules: [
			http,
			sessionStandIn,
			subjectRevocationStandIn,
			stand.module,
			kindsModule,
			entry,
			...extra,
		],
		config: { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) },
		runtime,
	});
	const opened = app.get(sessions);
	const signedIn = async (
		subject: string,
		amr: string[],
		authenticatedAt: number | "unknown" = runtime.clock.now(),
	) => {
		const { cookies } = await opened.complete(testRequest(), { subject, amr, authenticatedAt });
		return withCookie(cookies[0] ?? "");
	};
	return { app, opened, signedIn, asked: stand.asked };
}

const withCookie = (set: string) =>
	testRequest({ headers: new Map([["cookie", set.split(";")[0] ?? ""]]) });

describe("the entry requirements a second factor sets", () => {
	it("judges using a session and changing credentials, under mfa's name", async () => {
		const seen = contract<readonly EntryRequirement[]>("seen");
		const reader = defineModule({ name: "reader" }, (m) => [
			m.provide(seen).by((c) => c.collect(entryRequirements)),
		]);
		const { app } = await serve(new Set(), {}, [reader]);
		const mfa = app.get(seen).find((requirement) => requirement.name === "mfa");
		expect(mfa?.judges).toEqual(["use", "credentials"]);
	});

	it("asks a recent second factor to change credentials, and a second factor to use the session under required mode", async () => {
		const holding = new Set<string>();
		const { opened, signedIn } = await serve(holding, { required: true });
		const bare = await signedIn("bea", ["pwd"]);
		expect((await opened.enterFor(bare, "credentials")).kind).toBe("entered");
		expect((await opened.enterFor(bare, "use")).kind).toBe("short");
		holding.add("bea");
		expect((await opened.enterFor(bare, "credentials")).kind).toBe("short");
		const proved = await signedIn("bea", ["pwd", "otp", secondFactorAmr]);
		expect((await opened.enterFor(proved, "use")).kind).toBe("entered");
		expect((await opened.enterFor(proved, "credentials")).kind).toBe("entered");
		shift += recentMs + 1000;
		expect((await opened.enterFor(proved, "credentials")).kind).toBe("short");
		const raised = await opened.raise(proved, ["otp", secondFactorAmr]);
		const after = withCookie(raised?.cookies[0] ?? "");
		expect((await opened.enterFor(after, "credentials")).kind).toBe("entered");
	});

	it("never takes a sign-in at an unknown time as recent, a second factor it says it proved included", async () => {
		const { opened, signedIn } = await serve();
		const unknown = await signedIn("dee", ["fed"], "unknown");
		expect(await opened.enterFor(unknown, "credentials")).toMatchObject({ kind: "short" });
		const mapped = await signedIn("dee", ["fed", secondFactorAmr], "unknown");
		expect(await opened.enterFor(mapped, "credentials")).toMatchObject({ kind: "short" });
		const raised = await opened.raise(mapped, ["otp", secondFactorAmr]);
		const after = withCookie(raised?.cookies[0] ?? "");
		expect((await opened.enterFor(after, "credentials")).kind).toBe("entered");
	});

	it("takes only a raise that added a second factor as a recent second factor", async () => {
		const { opened, signedIn } = await serve(new Set(["cid"]));
		const request = await signedIn("cid", ["pwd"]);
		shift += recentMs + 1000;
		const raised = await opened.raise(request, ["pwd"]);
		const after = withCookie(raised?.cookies[0] ?? "");
		expect((await opened.enterFor(after, "credentials")).kind).toBe("short");
	});

	it("counts a second factor recent by session's one window: a fresh sign-in over an older proof is short", async () => {
		const { app, opened, signedIn } = await serve(new Set(["eve"]));
		const proved = await signedIn("eve", ["pwd", "otp", secondFactorAmr]);
		shift += recentMs + 1000;
		const raised = await opened.raise(proved, ["pwd"]);
		const fresh = withCookie(raised?.cookies[0] ?? "");
		expect((await opened.enterFor(fresh, "credentials")).kind).toBe("short");
		stopped = Date.now();
		const now = runtime.clock.now();
		const context = (at: number) =>
			({ subject: "eve", amr: [secondFactorAmr], authenticatedAt: at }) as never;
		expect(app.get(secondFactors).provenRecently(context(now - recentMs))).toBe(true);
		expect(app.get(secondFactors).provenRecently(context(now - recentMs - 1))).toBe(false);
	});

	it("asks mfa first at every credentials entry, so a store or a witness that cannot tell stops it", async () => {
		const { opened, signedIn, asked } = await serve(new Set(["fay"]), {
			unreadable: new Set(["gus"]),
		});
		const proved = await signedIn("fay", ["pwd", "otp", secondFactorAmr]);
		expect((await opened.enterFor(proved, "credentials")).kind).toBe("entered");
		expect(asked).toEqual(["fay credentials"]);
		const unread = await signedIn("gus", ["pwd", "otp", secondFactorAmr]);
		await expect(opened.enterFor(unread, "credentials")).rejects.toSatisfy(isUnavailable);
	});
});

it("takes only a second factor proven recently as proven, never a recent sign-in alone", async () => {
	const { app } = await serve();
	const now = runtime.clock.now();
	const at = (amr: string[], extra = {}) =>
		app
			.get(secondFactors)
			.provenRecently({ subject: "s", amr, authenticatedAt: now, ...extra } as never);
	expect(at(["pwd"])).toBe(false);
	expect(at(["pwd", secondFactorAmr])).toBe(true);
	expect(at(["pwd"], { raisedAmr: ["otp", secondFactorAmr], raisedAt: now })).toBe(true);
	expect(at(["pwd", secondFactorAmr], { authenticatedAtUnknown: true })).toBe(false);
});

it("refuses to boot under required mode unless a composed kind both counts and adds a second factor", async () => {
	await expect(
		serve(new Set(), { required: true, kinds: [kind(true, false)] }),
	).rejects.toBeInstanceOf(BootRefused);
	await expect(serve(new Set(), { required: true })).resolves.toBeDefined();
	await expect(serve(new Set(), { kinds: [kind(true, false)] })).resolves.toBeDefined();
});
