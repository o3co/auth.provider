import { quietRuntime } from "@mod/kernel/testing";
import { expect, it } from "vitest";
import { ignoredCertificates } from "../src/contract.ts";

const sent = new Map([["client-cert", ":MAMCAQE=:"]]);
const at = { dialect: "rfc9440", header: "client-cert" } as const;

it("warns of a certificate header it did not take, at most once a minute", () => {
	let now = 0;
	const warns = ignoredCertificates(at, quietRuntime({ clock: { now: () => now } }).clock);
	expect([warns(sent, undefined), warns(sent, undefined)]).toEqual([true, false]);
	now = 60_000;
	expect(warns(sent, undefined)).toBe(false);
	now = 60_001;
	expect(warns(sent, undefined)).toBe(true);
});

it("does not warn of a certificate it took, of no header, or where none is read", () => {
	const clock = quietRuntime().clock;
	const taken = { kind: "malformed" } as const;
	expect(ignoredCertificates(at, clock)(sent, taken)).toBe(false);
	expect(ignoredCertificates(at, clock)(new Map(), undefined)).toBe(false);
	expect(ignoredCertificates(undefined, clock)(sent, undefined)).toBe(false);
});
