import { expectTypeOf, test } from "vitest";
import type {
	RouteAdvertisement,
	RouteContribution,
	RouteContributionEntry,
	RouteContributionFactory,
	RouteHandler,
} from "../route-contribution.mjs";

test("RouteContribution has mountPath + handler + optional id + A2-β §4.2 fields", () => {
	// A2-β §4.2 adds routes?, before?, after? (additive amendment to A2-α §4.6).
	expectTypeOf<RouteContribution>().toEqualTypeOf<{
		readonly mountPath: string;
		readonly handler: RouteHandler;
		readonly id?: string;
		readonly routes?: readonly RouteAdvertisement[];
		readonly before?: readonly string[];
		readonly after?: readonly string[];
	}>();
});

test("RouteContributionEntry is union of value or factory", () => {
	type Entry = RouteContributionEntry<Record<never, never>>;
	expectTypeOf<Entry>().toEqualTypeOf<
		RouteContribution | RouteContributionFactory<Record<never, never>>
	>();
});

test("RouteContributionFactory returns RouteContribution sync or async", () => {
	type Factory = RouteContributionFactory<Record<never, never>>;
	expectTypeOf<Factory>().toMatchTypeOf<
		(deps: Record<never, never>) => RouteContribution | Promise<RouteContribution>
	>();
});
