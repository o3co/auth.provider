import { expectTypeOf, test } from "vitest";
import type {
  RouteContribution,
  RouteContributionEntry,
  RouteContributionFactory,
  RouteHandler,
} from "../route-contribution.mjs";

test("RouteContribution has mountPath + handler + optional id", () => {
  expectTypeOf<RouteContribution>().toEqualTypeOf<{
    readonly mountPath: string;
    readonly handler: RouteHandler;
    readonly id?: string;
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
