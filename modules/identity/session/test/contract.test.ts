import cookiesModule from "@mod/cookies/module";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import { assemble, defineModule, kernelConfig, type Module } from "@mod/kernel";
import { quietRuntime } from "@mod/kernel/testing";
import { revocations } from "@mod/subject-revocation";
import { subjectRevocationStandIn } from "@mod/subject-revocation/testing";
import { describe, expect, it } from "vitest";
import { entryRequirements, participants, sessions } from "../src/contract.ts";
import {
	failStandInListing,
	type PlaceOptions,
	type SessionsPlace,
	sessionStandIn,
	sessionsContract,
	standInLifetimeSeconds,
	standInListingCap,
} from "../src/testing.ts";

/** A place over the stand-in and the given modules, with the requirement and participant the contract test expects. */
async function placeOver(
	modules: readonly Module[] = [],
	{ credentialsJudged = true }: PlaceOptions = {},
): Promise<SessionsPlace> {
	let now = 1_800_000_000_000;
	let failing = false;
	const closed: string[] = [];
	const runtime = quietRuntime({ clock: { now: () => now } });
	const around = defineModule({ name: "around" }, (m) => [
		// Where credentials are judged, only a strong login changes them.
		...(credentialsJudged
			? [
					m.contribute(entryRequirements).by(() => ({
						name: "test",
						judges: ["credentials"],
						admits: async (context, level) =>
							level === "credentials" && !context.amr.includes("strong")
								? { kind: "short", answer: { error: "short" } }
								: { kind: "admit" },
					})),
				]
			: []),
		m.contribute(participants).by(() => ({
			name: "test",
			closing: async (session) => {
				if (failing) throw new Error("not yet");
				closed.push(session.context.subject);
			},
		})),
	]);
	const app = await assemble({
		modules: [http, cookiesModule, sessionStandIn, subjectRevocationStandIn, ...modules, around],
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

describe("entry requirements", () => {
	const asked: string[] = [];
	const requirement = (name: string) => ({
		name,
		judges: ["use" as const],
		admits: async () => {
			asked.push(name);
			return { kind: "admit" as const };
		},
	});
	const unsorted = defineModule({ name: "unsorted" }, (m) => [
		m.contribute(entryRequirements).by(() => requirement("b")),
		m.contribute(entryRequirements).by(() => requirement("a")),
	]);
	it("are asked in name order by the stand-in", async () => {
		const place = await placeOver([unsorted]);
		const done = await place.sessions.complete(place.request(), {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: place.now(),
		});
		asked.length = 0;
		expect((await place.sessions.enterFor(place.request(done.cookies), "use")).kind).toBe(
			"entered",
		);
		expect(asked).toEqual(["a", "b"]);
	});

	it("let nobody in whose subject is revoked while they are asked, by the stand-in", async () => {
		const gate: { open?: () => void; reached?: () => void } = {};
		const reached = new Promise<void>((resolve) => {
			gate.reached = resolve;
		});
		const opened = new Promise<void>((resolve) => {
			gate.open = resolve;
		});
		const waiting = defineModule({ name: "waiting" }, (m) => [
			m.contribute(entryRequirements).by(() => ({
				name: "waiting",
				judges: ["use"],
				admits: async () => {
					gate.reached?.();
					await opened;
					return { kind: "admit" };
				},
			})),
		]);
		const place = await placeOver([waiting]);
		const done = await place.sessions.complete(place.request(), {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: place.now(),
		});
		place.advance(60_000);
		const entering = place.sessions.enterFor(place.request(done.cookies), "use");
		await reached;
		await place.revokeSubject("alice");
		gate.open?.();
		expect(await entering).toEqual({ kind: "absent" });
	});
});

describe("participants", () => {
	it("are called one at a time in the order collected, past a failing one, by the stand-in", async () => {
		const calls: string[] = [];
		let running = 0;
		let overlapped = false;
		const participant = (name: string, fails: boolean) => ({
			name,
			closing: async () => {
				running++;
				overlapped ||= running > 1;
				calls.push(name);
				await new Promise((resolve) => setTimeout(resolve, 5));
				running--;
				if (fails) throw new Error("not yet");
			},
		});
		const two = defineModule({ name: "two" }, (m) => [
			m.contribute(participants).by(() => participant("b", true)),
			m.contribute(participants).by(() => participant("a", false)),
		]);
		const place = await placeOver([two]);
		const done = await place.sessions.complete(place.request(), {
			subject: "alice",
			amr: ["pwd"],
			authenticatedAt: place.now(),
		});
		expect((await place.sessions.close(done.session.id)).kind).toBe("pending");
		expect(calls).toEqual(["b", "a"]);
		expect(place.closed).toEqual(["alice"]);
		expect(overlapped).toBe(false);
	});
});
