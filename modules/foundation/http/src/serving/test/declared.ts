import type { Route } from "../../contract.ts";

/** A test's route as boot checks it: a GET that changes no state, any other with a test's reasons; what it declares stands. */
export const declared = (route: Route): Route =>
	route.method === "GET"
		? { changesState: false, ...route }
		: { crossSite: "a test route", unlimited: "a test route", ...route };
