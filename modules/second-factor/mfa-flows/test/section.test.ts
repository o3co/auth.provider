import { expect, it } from "vitest";
import { type Settings, section } from "../src/section.ts";

const parses = (settings: object) => section.safeParse(settings).success;
const times = { "transaction-lifetime": 600, window: 300 };
const day = 86_400;
const lockoutTimes = { backoff: 900, "max-backoff": day, "budget-window": 7 * day, memory: day };
/** Settings placed where `key` lies: at the top, or in `lockout`. */
const at = (key: string, settings: object) => (key in times ? settings : { lockout: settings });
/** The time `key` was read as, in seconds. */
const timeOf = (read: Settings, key: string) =>
	(key in times ? read : read.lockout)[key as keyof typeof times & keyof typeof lockoutTimes];

it("defaults each setting, its times read as an operator writes them, and refuses one it does not know", () => {
	const lockout = { threshold: 5, budget: 10, "hard-limit": 100, ...lockoutTimes };
	const all = { "attempts-per-transaction": 5, requests: 60, ...times, lockout };
	expect([section.parse({}), section.parse({ lockout: {} })]).toEqual([all, all]);
	expect(parses({ "transaction-lifetim": "10m" })).toBe(false);
});

it.each(Object.keys({ ...times, ...lockoutTimes }))(
	"reads %s written with its unit, in whole seconds, never a bare number",
	(key) => {
		// memory is at least 1h; the others take 20m.
		const [written, read] = key === "memory" ? ["2h", 7200] : ["20m", 1200];
		expect(timeOf(section.parse(at(key, { [key]: written })), key)).toBe(read);
		const refused = [600, "600", "1500ms"].map((value) => parses(at(key, { [key]: value })));
		expect(refused).toEqual([false, false, false]);
	},
);

it.each([
	["transaction-lifetime", 60, 1800],
	["window", 1, 86_400],
])("takes %s from %is to %is, and nothing outside", (key, low, high) => {
	const seconds = [low - 1, low, high, high + 1].map((n) => parses({ [key]: `${n}s` }));
	expect(seconds).toEqual([false, true, true, false]);
});

it("takes the other numbers whole and within their bounds", () => {
	const bounds = { "attempts-per-transaction": [2, 10], requests: [1, 100_000] };
	for (const [name, [min = 0, max = 0]] of Object.entries(bounds)) {
		const taken = [min - 1, min, min + 0.5, max, max + 1].map((value) => parses({ [name]: value }));
		expect([name, taken]).toEqual([name, [false, true, false, true, false]]);
	}
});

it.each(["threshold", "budget", "hard-limit"])(
	"takes lockout's %s up to 100, the most consecutive failures NIST SP 800-63B rev 4 §3.2.2 allows, and refuses 101",
	(key) => {
		// The order threshold ≤ budget ≤ hard-limit is rate-limit's to judge, at boot.
		expect([100, 101].map((n) => parses({ lockout: { [key]: n } }))).toEqual([true, false]);
	},
);

it("takes a lockout memory from 1h, and refuses one a second shorter", () => {
	expect(["3600s", "3599s"].map((memory) => parses({ lockout: { memory } }))).toEqual([
		true,
		false,
	]);
});

it.each([
	["transaction-seconds", "transaction-lifetime"],
	["window-seconds", "window"],
	["backoff-seconds", "backoff"],
	["max-backoff-seconds", "max-backoff"],
	["budget-window-seconds", "budget-window"],
	["memory-seconds", "memory"],
])("refuses %s, the name in seconds %s replaced", (old, key) => {
	expect(parses(at(key, { [old]: 120 }))).toBe(false);
});
