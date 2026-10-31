import { expect, it } from "vitest";
import rpLogout from "../src/module.ts";
import { registration } from "../src/registration/registration.ts";
import { section } from "../src/section.ts";

it.each([
	["remember-for", "59s", "1m", "30d", "2592001s"],
	["notify-within", "59s", "1m", "7d", "604801s"],
	["sweep-interval", "0s", "1s", "1h", "3601s"],
	["confirm-within", "59s", "1m", "15m", "901s"],
])("takes %s from its least to its most, written with its unit", (key, under, low, high, over) => {
	const takes = (value: unknown) => section.safeParse({ [key]: value }).success;
	expect([under, low, high, over, 60, "60"].map(takes)).toEqual([
		false,
		true,
		true,
		false,
		false,
		false,
	]);
});

it("remembers and notifies for a day, sweeps every minute, waits five minutes for a person to confirm and takes 60 requests a minute per source, where nothing is set", () => {
	expect(section.parse({})).toEqual({
		"remember-for": 86_400,
		"notify-within": 86_400,
		"sweep-interval": 60,
		"confirm-within": 300,
		requests: 60,
		window: 60,
	});
});

it.each(["remember-seconds", "notify-seconds", "sweep-seconds"])(
	"refuses %s, a name in seconds",
	(key) => {
		expect(section.safeParse({ [key]: 60 }).success).toBe(false);
	},
);

it("sends a client back nowhere and asks for the session on both channels, where its metadata says nothing", async () => {
	expect((await registration.schema["~standard"].validate({})) as unknown).toEqual({
		value: {
			"post-logout-redirect-uris": [],
			"frontchannel-logout-session-required": true,
			"backchannel-logout-session-required": true,
		},
	});
});

it("takes an https error page, http only on a loopback host, and refuses a loopback one in production", () => {
	expect(section.parse({ "error-page": "https://pages.example/logout-error" })["error-page"]).toBe(
		"https://pages.example/logout-error",
	);
	expect(section.safeParse({ "error-page": "http://pages.example/logout-error" }).success).toBe(
		false,
	);
	const loopback = section.parse({ "error-page": "http://127.0.0.1:8080/logout-error" });
	expect(rpLogout.refusedInProduction?.(loopback)?.map((r) => r.key)).toEqual(["error-page"]);
	expect(rpLogout.refusedInProduction?.(section.parse({}))).toEqual([]);
});
