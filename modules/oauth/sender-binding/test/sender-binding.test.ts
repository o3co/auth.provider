import type { HttpRequest } from "@mod/http";
import http from "@mod/http/module";
import { httpConfig, testRequest } from "@mod/http/testing";
import issuerModule from "@mod/issuer/module";
import { issuerConfig } from "@mod/issuer/testing";
import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { expect, it } from "vitest";
import { sameBinding, senderBinding, senderBindings } from "../src/contract.ts";
import senderBindingModule from "../src/module.ts";

/** Members whose proofs were read, in order. */
const reads: string[] = [];

const kind = (member: string, header: string, explicit = false) =>
	defineModule({ name: `binding-${member}`, replicaSafe: false, takes: [] }, (m) => [
		m.contribute(senderBindings).by(() => ({
			member,
			tokenType: member.toUpperCase(),
			...(explicit ? { explicit: true } : {}),
			read: async (request: HttpRequest, _scene, issuer) => {
				reads.push(member);
				const value = request.headers.get(header);
				if (value === "bad") return { kind: "refused", error: `invalid_${member}` };
				return value ? { kind: "bound", confirmation: `${value}@${issuer}` } : { kind: "absent" };
			},
		})),
	]);

/** Assembles the kinds in the order given, under the section given. */
const readerWith = async (
	section: Record<string, unknown>,
	...kinds: ReturnType<typeof kind>[]
) => {
	const app = await assemble({
		modules: [http, issuerModule, senderBindingModule, ...kinds],
		config: {
			...kernelConfig(),
			...httpConfig(),
			...issuerConfig(),
			"sender-binding": section,
		},
	});
	return app.get(senderBinding);
};
const reader = (...kinds: ReturnType<typeof kind>[]) => readerWith({}, ...kinds);
const request = (headers: Record<string, string>) =>
	testRequest({ method: "POST", headers: new Map(Object.entries(headers)) });
const scene = { kind: "issue" } as const;

it("reads the binding a request proves through every kind, and refuses two at once", async () => {
	const b = await reader(kind("one", "x-one"), kind("two", "x-two"));
	expect(await b.bindingOf(request({}), scene)).toEqual({ kind: "none" });
	expect(await b.bindingOf(request({ "x-one": "bad" }), scene)).toEqual({
		kind: "refused",
		error: "invalid_one",
	});
	expect((await b.bindingOf(request({ "x-one": "a", "x-two": "b" }), scene)).kind).toBe(
		"multiple_bindings",
	);
	expect(await b.bindingOf(request({ "x-one": "thumb" }), scene)).toEqual({
		kind: "bound",
		binding: { member: "one", confirmation: "thumb@https://issuer.example", tokenType: "ONE" },
	});
	expect([b.tokenTypeOf("two"), b.tokenTypeOf("three")]).toEqual(["TWO", undefined]);
});

it("answers a kind's refusal over any binding another kind finds", async () => {
	const b = await reader(kind("one", "x-one"), kind("two", "x-two"));
	expect(await b.bindingOf(request({ "x-one": "bad", "x-two": "b" }), scene)).toEqual({
		kind: "refused",
		error: "invalid_one",
	});
	expect(await b.bindingOf(request({ "x-one": "a", "x-two": "bad" }), scene)).toEqual({
		kind: "refused",
		error: "invalid_two",
	});
});

it("reads kinds in the order of their members, whatever order they were assembled in", async () => {
	for (const b of [
		await reader(kind("one", "x-one"), kind("two", "x-two")),
		await reader(kind("two", "x-two"), kind("one", "x-one")),
	]) {
		reads.length = 0;
		expect(await b.bindingOf(request({ "x-one": "bad", "x-two": "bad" }), scene)).toEqual({
			kind: "refused",
			error: "invalid_one",
		});
		// The first refusal stops the reading, so no later kind spends its proof.
		expect(reads).toEqual(["one"]);
	}
});

it("takes two bindings as the same only for the same kind and key, or when both are absent", () => {
	const bound = (member: string, confirmation: string) => ({
		member,
		confirmation,
		tokenType: "T",
	});
	expect(sameBinding(bound("jkt", "k1"), bound("jkt", "k1"))).toBe(true);
	expect(sameBinding(bound("jkt", "k1"), bound("jkt", "k2"))).toBe(false);
	expect(sameBinding(bound("jkt", "k1"), bound("x5t#S256", "k1"))).toBe(false);
	expect(sameBinding(bound("jkt", "k1"), undefined)).toBe(false);
	expect(sameBinding(undefined, undefined)).toBe(true);
});

it("takes an explicit kind's binding over an ambient one, by default, and refuses two of one tier", async () => {
	const b = await reader(
		kind("one", "x-one", true),
		kind("two", "x-two"),
		kind("three", "x-three"),
	);
	expect(await b.bindingOf(request({ "x-one": "a", "x-two": "b" }), scene)).toEqual({
		kind: "bound",
		binding: { member: "one", confirmation: "a@https://issuer.example", tokenType: "ONE" },
	});
	expect(await b.bindingOf(request({ "x-two": "b", "x-three": "c" }), scene)).toEqual({
		kind: "multiple_bindings",
	});
	const twoExplicit = await reader(kind("one", "x-one", true), kind("two", "x-two", true));
	expect(await twoExplicit.bindingOf(request({ "x-one": "a", "x-two": "b" }), scene)).toEqual({
		kind: "multiple_bindings",
	});
});

it("refuses any two bindings where the section asks for strict mutual exclusion", async () => {
	const b = await readerWith(
		{ dispatch: "strict-mutual-exclusion" },
		kind("one", "x-one", true),
		kind("two", "x-two"),
	);
	expect(await b.bindingOf(request({ "x-one": "a", "x-two": "b" }), scene)).toEqual({
		kind: "multiple_bindings",
	});
	await expect(readerWith({ dispatch: "first" }, kind("one", "x-one"))).rejects.toBeInstanceOf(
		BootRefused,
	);
});
