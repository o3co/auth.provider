/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 */

/**
 * The `subjectRevocationParticipants` contribution kind, booted through
 * `createApp`: each feature contributes, under a name, the participant that
 * clears its own state for a revoked subject; boot projects them, in
 * registration order, as `subjectRevocationParticipantResolver`, and refuses a
 * malformed contribution, a second claimant of a name, an override and a host
 * collector.
 */

import { describe, expect, it } from "vitest";
import { BootError } from "#/boot/types.mjs";
import { createApp, defineModule, type Module } from "#/index.mjs";
import { SYNTHETIC_COMPONENT_KEYS } from "#/modules/manifest/synthetic-keys.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import type {
	SubjectRevocationParticipant,
	SubjectRevocationParticipantResolver,
} from "#/user-sessions/subjectRevocationParticipants.mjs";

const boot = (modules: readonly Module[], extra: Partial<Parameters<typeof createApp>[0]> = {}) =>
	createApp({
		modules,
		bootstrapComponents: {
			config: makeValidCoreConfig(),
			pathResolver: (p: string) => p,
		} as never,
		...extra,
	});

const refusal = async (promise: Promise<unknown>): Promise<BootError> => {
	const err = await promise.then(
		() => undefined,
		(caught: unknown) => caught,
	);
	expect(err).toBeInstanceOf(BootError);
	return err as BootError;
};

/** A module contributing `participants` (or overriding them) and nothing else. */
const contributing = (
	name: string,
	participants: unknown,
	channel: "contributes" | "overrides" = "contributes",
) => defineModule({ name, [channel]: { subjectRevocationParticipants: participants } } as never);

const participant = (runs: string[], tag: string): SubjectRevocationParticipant => ({
	async run({ subject }) {
		runs.push(`${tag}:${subject}`);
	},
});

const resolverOf = async (modules: readonly Module[]) => {
	const handle = await boot(modules);
	return handle.components.subjectRevocationParticipantResolver as
		| SubjectRevocationParticipantResolver
		| undefined;
};

describe("subjectRevocationParticipants — registration", () => {
	it("is a synthetic key", () => {
		expect(SYNTHETIC_COMPONENT_KEYS.has("subjectRevocationParticipantResolver")).toBe(true);
	});

	it("projects every participant by name, in registration order", async () => {
		const runs: string[] = [];
		const resolver = await resolverOf([
			contributing("test:first", { "first-feature": () => participant(runs, "first") }),
			contributing("test:second", {
				"second-feature": () => participant(runs, "second"),
				"third-feature": async () => participant(runs, "third"),
			}),
		]);

		expect(resolver).toBeDefined();
		const names = [...(resolver?.entries() ?? [])].map(([name]) => name);
		expect(names).toEqual(["first-feature", "second-feature", "third-feature"]);
		await resolver?.get("second-feature")?.run({ subject: "u-1" });
		expect(runs).toEqual(["second:u-1"]);
	});

	it("is present and empty when nothing contributes", async () => {
		const resolver = await resolverOf([]);
		expect(resolver).toBeDefined();
		expect([...(resolver?.entries() ?? [])]).toEqual([]);
	});

	it("registers the run it checked: a run swapped afterwards is not the one called", async () => {
		const runs: string[] = [];
		const answered = participant(runs, "checked") as { run: SubjectRevocationParticipant["run"] };
		const resolver = await resolverOf([contributing("test:swap", { feature: () => answered })]);
		answered.run = async () => void runs.push("swapped");

		await resolver?.get("feature")?.run({ subject: "u-1" });
		expect(runs).toEqual(["checked:u-1"]);
		expect(Object.isFrozen(resolver?.get("feature"))).toBe(true);
	});
});

describe("subjectRevocationParticipants — refusals", () => {
	it("refuses a name two modules contribute (duplicate-contribute)", async () => {
		const err = await refusal(
			boot([
				contributing("test:a", { feature: () => participant([], "a") }),
				contributing("test:b", { feature: () => participant([], "b") }),
			]),
		);
		expect(err.reason).toBe("duplicate-contribute");
		expect(err.details).toMatchObject({
			kind: "subjectRevocationParticipants",
			identity: "feature",
			modules: ["test:a", "test:b"],
		});
	});

	it.each([
		["an array", [() => participant([], "x")]],
		["a function", () => participant([], "x")],
		["null", null],
	])("refuses a container that is %s (contribution-malformed)", async (_label, container) => {
		const err = await refusal(boot([contributing("test:bad", container)]));
		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({
			module: "test:bad",
			kind: "subjectRevocationParticipants",
			channel: "contributes",
		});
		expect(err.details).not.toHaveProperty("name");
	});

	it("refuses an entry that is not a factory (contribution-malformed)", async () => {
		const err = await refusal(boot([contributing("test:bad", { feature: participant([], "x") })]));
		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({
			kind: "subjectRevocationParticipants",
			name: "feature",
		});
	});

	it.each([
		["empty", ""],
		["upper-case", "Feature"],
		["with a space", "my feature"],
		["with a control character", "feature\n"],
		["longer than 64 characters", `a${"b".repeat(64)}`],
	])("refuses a name that is %s (contribution-malformed)", async (_label, name) => {
		const err = await refusal(
			boot([contributing("test:bad", { [name]: () => participant([], "x") })]),
		);
		expect(err.reason).toBe("contribution-malformed");
		expect(err.details).toMatchObject({ kind: "subjectRevocationParticipants", name });
	});

	it("refuses an override of a participant (contribution-kind-guarded)", async () => {
		const err = await refusal(
			boot([
				contributing("test:owner", { feature: () => participant([], "owner") }),
				contributing("test:other", { feature: () => participant([], "other") }, "overrides"),
			]),
		);
		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toMatchObject({
			kind: "subjectRevocationParticipants",
			channel: "overrides",
			module: "test:other",
			name: "feature",
		});
	});

	it("refuses a host collector for the kind (contribution-kind-guarded)", async () => {
		const err = await refusal(
			boot([], {
				contributionKinds: {
					subjectRevocationParticipants: {
						kind: "name-keyed",
						register: () => {},
						replace: () => {},
						get: () => undefined,
						entries: () => new Map().entries(),
					},
				} as never,
			}),
		);
		expect(err.reason).toBe("contribution-kind-guarded");
		expect(err.details).toMatchObject({ kind: "subjectRevocationParticipants" });
	});

	it.each([
		["null", null],
		["an object without run", {}],
		["a bare function", async () => {}],
	])("refuses a factory that answers %s (contribute-factory-failed)", async (_label, value) => {
		const err = await refusal(boot([contributing("test:bad", { feature: () => value })]));
		expect(err.reason).toBe("contribute-factory-failed");
		expect(err.details).toMatchObject({
			kind: "subjectRevocationParticipants",
			name: "feature",
		});
	});
});
