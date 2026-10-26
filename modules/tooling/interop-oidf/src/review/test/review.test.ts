import { describe, expect, it } from "vitest";
import type { ModuleRun } from "../../results/results.ts";
import { reviewPages } from "../review.ts";

const variant = { client_auth_type: "client_secret_basic" };
const page = (source: string, regexp: string) =>
	({
		result: "REVIEW",
		src: "ExpectSuccessfulLogoutPage",
		msg: "The server must log the user out - upload a screenshot of the successful logout page.",
		page_source: source,
		content_type: "application/json",
		matched_regexp: regexp,
	}) as ModuleRun["log"][number];

describe("the pages the suite's browser kept for a person to review", () => {
	it("gives each review test's page as a file of its own, with what the suite asks of it", () => {
		const runs: ModuleRun[] = [
			{
				testModule: "oidcc-rp-initiated-logout-no-params",
				variant,
				instance: "a1",
				info: { status: "FINISHED", result: "REVIEW" },
				log: [
					{ src: "Other", msg: "a step", result: "SUCCESS" },
					page('<html>{"logged_out":true}</html>', "logged_out"),
				],
			},
			{
				testModule: "oidcc-server",
				variant,
				instance: "b2",
				info: { status: "FINISHED", result: "PASSED" },
				log: [page("<html>not for review</html>", "x")],
			},
		];
		expect(reviewPages(runs)).toEqual([
			{
				file: "oidcc-rp-initiated-logout-no-params.html",
				test: "oidcc-rp-initiated-logout-no-params",
				instance: "a1",
				condition: "ExpectSuccessfulLogoutPage",
				asks: "The server must log the user out - upload a screenshot of the successful logout page.",
				matched: "logged_out",
				contentType: "application/json",
				page: '<html>{"logged_out":true}</html>',
			},
		]);
	});

	it("names a test's second page, and a second test of the same name, apart", () => {
		const twice: ModuleRun = {
			testModule: "oidcc-prompt-login",
			variant,
			instance: "c3",
			info: { status: "FINISHED", result: "REVIEW" },
			log: [page("<html>one</html>", "Log in"), page("<html>two</html>", "Log in")],
		};
		const files = reviewPages([twice, { ...twice, instance: "d4" }]).map((p) => p.file);
		expect(files).toEqual([
			"oidcc-prompt-login.html",
			"oidcc-prompt-login-2.html",
			"oidcc-prompt-login-3.html",
			"oidcc-prompt-login-4.html",
		]);
	});

	it("tells a review test that kept no page, for a person to look at it in the suite's log", () => {
		const bare: ModuleRun = {
			testModule: "oidcc-max-age-1",
			variant,
			instance: "e5",
			info: { status: "FINISHED", result: "REVIEW" },
			log: [{ src: "ExpectSecondLoginPage", msg: "upload a screenshot", result: "REVIEW" }],
		};
		const pages = reviewPages([bare]);
		expect(pages).toEqual([
			expect.objectContaining({ file: "oidcc-max-age-1.html", condition: "ExpectSecondLoginPage" }),
		]);
		expect(pages[0]?.page).toBeUndefined();
	});
});
