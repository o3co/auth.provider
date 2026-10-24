import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { describe, expect, it } from "vitest";
import { closingParticipants, type EntryJudge, entryJudge, sessions } from "../src/contract.ts";
import {
	failStandInListing,
	type PlaceOptions,
	type SessionsPlace,
	sessionStandIn,
	sessionsContract,
	standInLifetimeSeconds,
	standInListingCap,
} from "../src/testing.ts";

/** A place over the stand-in and the given modules, with stand-ins for `session`'s seams as the contract test expects them. */
async function placeOver(
	modules: readonly Module[] = [],
	{ credentialsJudged = true }: PlaceOptions = {},
	seams: { readonly judge?: EntryJudge; readonly none?: true } = {},
): Promise<SessionsPlace> {
	let now = 1_800_000_000_000;
	let failing = false;
	const closed: string[] = [];
	const runtime = quietRuntime({ clock: { now: () => now } });
	// Where credentials are judged, only a strong login changes them.
	const judge: EntryJudge = seams.judge ?? {
		judge: async (context, level) =>
			credentialsJudged && level === "credentials" && !context.amr.includes("strong")
				? { kind: "short", requirement: "test", answer: { error: "short" } }
				: { kind: "admit", judged: credentialsJudged && level === "credentials" },
	};
	const around = defineModule({ name: "around", takes: [] }, (m) => [
		m.contribute(entryJudge).by(() => judge),
		m.contribute(closingParticipants).by(() => ({
			closing: async (session) => {
				if (failing) return [{ participant: "test", kind: "Error" }];
				closed.push(session.context.subject);
				return [];
			},
		})),
	]);
	const app = await assemble({
		modules: [
			http,
			cookiesModule,
			sessionStandIn,
			subjectRevocationStandIn,
			...modules,
			...(seams.none ? [] : [around]),
		],
		config: { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) },
		runtime,
	});
	return {
		sessions: app.get(sessions),
		now: () => now,
		advance: (ms) => {
			now += ms;
		},
		lifetimeMs: standInLifetimeSeconds * 1000,
		request: (setCookies = []) =>
			testRequest({
				headers: new Map([["cookie", setCookies.map((c) => c.split(";")[0]).join("; ")]]),
				source: { scheme: "https" },
			}),
		revokeSubject: (subject) => app.get(revocations).record(subject),
		closed,
		failClosing: (on) => {
			failing = on;
		},
		listingCap: standInListingCap,
		failNextListing: () => failStandInListing(app.get(sessions)),
	};
}

sessionsContract("the stand-in, over subject-revocation's stand-in", (options) =>
	placeOver([], options),
);

describe("the stand-in's seams", () => {
	const facts = (place: SessionsPlace, amr = ["pwd"]) => ({
		subject: "alice",
		amr,
		authenticatedAt: place.now(),
	});

	it("takes no seam contributed as no requirement and no participant, the credentials floor still kept", async () => {
		const place = await placeOver([], {}, { none: true });
		const done = await place.sessions.complete(place.request(), facts(place));
		const entering = (level: "use" | "credentials") =>
			place.sessions.enterFor(place.request(done.cookies), level);
		expect((await entering("use")).kind).toBe("entered");
		expect((await entering("credentials")).kind).toBe("entered");
		place.advance(301_000);
		expect(await entering("credentials")).toMatchObject({ kind: "short", requirement: "session" });
		expect((await place.sessions.close(done.session.id)).kind).toBe("closed");
	});

	it("lets nobody in whose subject is revoked while the requirements are asked", async () => {
		const gate: { open?: () => void; reached?: () => void } = {};
		const reached = new Promise<void>((resolve) => {
			gate.reached = resolve;
		});
		const opened = new Promise<void>((resolve) => {
			gate.open = resolve;
		});
		const waiting: EntryJudge = {
			judge: async () => {
				gate.reached?.();
				await opened;
				return { kind: "admit", judged: false };
			},
		};
		const place = await placeOver([], {}, { judge: waiting });
		const done = await place.sessions.complete(place.request(), facts(place));
		place.advance(60_000);
		const entering = place.sessions.enterFor(place.request(done.cookies), "use");
		await reached;
		await place.revokeSubject("alice");
		gate.open?.();
		expect(await entering).toEqual({ kind: "absent" });
	});
});

it("takes every handle its stand-in's takes name, the seams collected though none is contributed", async () => {
	const config = { ...kernelConfig(), ...httpConfig({ "public-origin": "https://as.example" }) };
	const modules = [http, cookiesModule, sessionStandIn, subjectRevocationStandIn];
	expect(await takesUnused({ modules, config })).toEqual({});
});
