import type { Guarantee } from "@mod/store";
import { expect, expectTypeOf, it } from "vitest";
import type { StatedNeeds } from "../src/needs.ts";

type Needs = { readonly durable: true; readonly replicated: true; readonly endsWithinMs: 600_000 };

it("maps each need stated true, and no bound", () => {
	expectTypeOf<StatedNeeds<Needs>>().toEqualTypeOf<"durable" | "replicated">();
	const mapped = { durable: "durable", replicated: "replicated" } satisfies Record<
		StatedNeeds<Needs>,
		Guarantee
	>;
	// @ts-expect-error A need stated true with nothing mapped fails the type check.
	const unmapped = { durable: "durable" } satisfies Record<StatedNeeds<Needs>, Guarantee>;
	expect([mapped, unmapped]).toHaveLength(2);
});
