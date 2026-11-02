import { defineModule } from "@mod/kernel";
import { issuancePolicies } from "@mod/tokens";
import { afterEach, describe, expect, it } from "vitest";
import {
	advance,
	callback,
	eventsDeclared,
	issuer,
	request,
	serve,
	stopServed,
} from "../../../test/harness.ts";

afterEach(() => stopServed());
afterEach(() => eventsDeclared());

describe("the flow: a fresh login measured again before the code", () => {
	type Served = Awaited<ReturnType<typeof serve>>;
	const asked = request({ client_id: "third", max_age: "10" });
	const at = (res: { at?: URL | undefined }) => `${res.at?.origin}${res.at?.pathname}`;

	/** Accepts the consent `res` sends the browser to, and follows the answer back to the endpoint. */
	const accept = async (s: Served, res: { at?: URL | undefined }, cookie: string) => {
		const answered = await fetch(`${s.base}/oauth/consent`, {
			method: "POST",
			redirect: "manual",
			headers: {
				"content-type": "application/x-www-form-urlencoded",
				cookie,
				origin: issuer,
				"x-forwarded-proto": "https",
				"x-forwarded-for": "198.51.100.1",
			},
			body: new URLSearchParams({
				challenge: res.at?.searchParams.get("challenge") ?? "",
				decision: "accept",
			}),
		});
		return s.authorize(new URL(answered.headers.get("location") ?? "").search.slice(1), cookie);
	};

	/** A request with max_age=10 whose consent is given 20 seconds after its login. */
	const consentedLate = async () => {
		const s = await serve();
		const cookie = await s.login();
		const consent = await s.authorize(asked, cookie);
		expect(at(consent)).toBe(`${issuer}/consent`);
		advance(20_000);
		return { s, back: await accept(s, consent, cookie) };
	};

	it("sends a request whose consent outlasted its max_age to log in, giving no code [guarantee-2-b] [oidc-core-3.1.2.1-r]", async () => {
		const { back } = await consentedLate();
		expect(at(back)).toBe(`${issuer}/login`);
		expect(back.at?.searchParams.get("max_age")).toBe("10");
	});

	it("gives a request whose consent took longer than its max_age its code after one more login, consent not asked again", async () => {
		const { s, back } = await consentedLate();
		const resume = new URL(back.at?.searchParams.get("redirect_to") ?? "");
		const res = await s.authorize(resume.search.slice(1), await s.login());
		expect(res.at?.searchParams.has("code")).toBe(true);
	});

	/** An issuance policy that takes two seconds to judge. */
	const slow = defineModule({ name: "slow", replicaSafe: false, takes: [] }, (m) => [
		m.contribute(issuancePolicies).by(() => ({
			name: "slow",
			judge: async () => {
				advance(2000);
				return { kind: "allowed" };
			},
		})),
	]);

	it("measures max_age again before the code, so a step that outlasts it sends the browser to log in [guarantee-2-b] [oidc-core-3.1.2.1-r]", async () => {
		const s = await serve({ extra: [slow] });
		const cookie = await s.login();
		advance(9900);
		const res = await s.authorize(request({ max_age: "10" }), cookie);
		expect([at(res), res.at?.searchParams.has("code")]).toEqual([`${issuer}/login`, false]);
		const resume = new URL(res.at?.searchParams.get("redirect_to") ?? "");
		const again = await s.authorize(resume.search.slice(1), await s.login());
		expect(again.at?.searchParams.has("code")).toBe(true);
	});

	it("refuses a silent request that a step makes outlast its max_age with login_required, giving no code [guarantee-2-b]", async () => {
		const s = await serve({ extra: [slow] });
		const cookie = await s.login();
		advance(9900);
		const res = await s.authorize(request({ max_age: "10", prompt: "none" }), cookie);
		expect([at(res), res.at?.searchParams.get("error"), res.at?.searchParams.has("code")]).toEqual([
			callback,
			"login_required",
			false,
		]);
	});
});
