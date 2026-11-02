import { describe, expect, it } from "vitest";
import { drive, makePlan, type State, type SuiteCall, stateOf } from "../drive.ts";

/** A suite whose tests go through the states each is scripted with, keeping every call. */
function fakeSuite(script: Record<string, State[]> = {}) {
	const calls: string[] = [];
	const states = new Map<string, State[]>();
	let next = 0;
	const call: SuiteCall = async (method, path, body) => {
		calls.push(`${method} ${path}${body === undefined ? "" : ` ${JSON.stringify(body)}`}`);
		if (method === "POST" && path.startsWith("api/plan?")) {
			return {
				status: 201,
				body: { id: "plan-1", modules: [{ testModule: "a" }, { testModule: "b" }] },
			};
		}
		if (method === "POST") {
			const test = new URLSearchParams(path.split("?")[1]).get("test") ?? "";
			const id = `${test}-${++next}`;
			states.set(id, [...(script[test] ?? ["WAITING", "FINISHED"])]);
			return { status: 201, body: { id } };
		}
		const waited = path.match(/^api\/runner\/([^/]+)\/wait-state\?states=([^&]+)/);
		if (waited) {
			const [, id = "", wanted = ""] = waited;
			const left = states.get(id) ?? [];
			const now = left[0];
			if (now === undefined) return { status: 404, body: {} };
			if (wanted.split(",").includes(now)) {
				if (left.length > 1) left.shift();
				return { status: 200, body: { state: now } };
			}
			left.shift();
			return { status: 200, body: { timeout: true } };
		}
		if (path.startsWith("api/info/")) return { status: 200, body: { status: "FINISHED" } };
		return { status: 404, body: {} };
	};
	return { suite: call, calls };
}

const quick = { withinMs: 5_000 };

describe("driving the suite's relying party tests", () => {
	it("makes a plan under its variant and configuration", async () => {
		const { suite, calls } = fakeSuite();
		const plan = await makePlan(
			suite,
			"oidcc-client-test-plan",
			{ response_type: "code" },
			{
				alias: "x",
			},
		);
		expect(plan).toEqual({ id: "plan-1", modules: [{ testModule: "a" }, { testModule: "b" }] });
		expect(calls).toEqual([
			'POST api/plan?planName=oidcc-client-test-plan&variant=%7B%22response_type%22%3A%22code%22%7D {"alias":"x"}',
		]);
	});

	it("lets the app act once the test waits for it, and waits for the suite to end it", async () => {
		const { suite, calls } = fakeSuite({ a: ["CONFIGURED", "WAITING", "RUNNING", "FINISHED"] });
		const plan = await makePlan(suite, "p", {}, {});
		let actedWhen = -1;
		const driven = await drive(
			suite,
			plan,
			"a",
			async () => {
				actedWhen = calls.length;
				return "side";
			},
			quick,
		);
		expect(driven).toEqual({ testModule: "a", instance: "a-1", side: "side", ended: "FINISHED" });
		expect(calls.slice(0, actedWhen).filter((c) => c.includes("wait-state"))).toHaveLength(2);
	});

	it("never lets the app act on a test that ended before it waited", async () => {
		const { suite } = fakeSuite({ a: ["FINISHED"] });
		const plan = await makePlan(suite, "p", {}, {});
		let acted = false;
		await expect(
			drive(
				suite,
				plan,
				"a",
				async () => {
					acted = true;
				},
				quick,
			),
		).rejects.toThrow("a ended FINISHED before the app was asked");
		expect(acted).toBe(false);
	});

	it("refuses an answer the suite should not give", async () => {
		const broken: SuiteCall = async () => ({ status: 500, body: {} });
		await expect(makePlan(broken, "p", {}, {})).rejects.toThrow(
			"the suite answered 500 to POST api/plan",
		);
		await expect(stateOf(broken, "t", ["WAITING"], quick)).rejects.toThrow(
			"the suite answered 500 to the wait for t",
		);
	});

	it("reads a test no longer running from its info, and gives up past its time", async () => {
		const { suite } = fakeSuite();
		expect(await stateOf(suite, "gone", ["FINISHED"], quick)).toBe("FINISHED");
		const stuck: SuiteCall = async () => ({ status: 200, body: { timeout: true } });
		await expect(stateOf(stuck, "t", ["WAITING"], { withinMs: 50 })).rejects.toThrow(
			"t was not WAITING in time",
		);
	});
});
