import { describe, expect, it } from "vitest";
import { frontChannelPage, loggedOutPage } from "../page.ts";

const at = { issuer: "https://as.example", session: "s1" };
const frames = [{ uri: "https://app.example/fc", withSession: true }];

describe("the pages a logout ends on", () => {
	it("says, on the front-channel page, that the user is logged out, the frames hidden beside it", () => {
		const page = frontChannelPage(frames, at);
		expect(page?.html).toContain("<title>Logged out</title>");
		expect(page?.html).toContain("You are logged out.");
		expect(page?.html).toContain("<iframe");
	});

	it("says so on a page with no frame, and has no script where there is nowhere to go next", () => {
		const page = loggedOutPage({});
		expect(page.html).toContain("<title>Logged out</title>");
		expect(page.html).toContain("You are logged out.");
		expect(page.html).not.toContain("<script");
		expect(page.html).not.toContain("<iframe");
		expect(page.loads).toEqual({ frames: [], scripts: [] });
	});

	it("moves the browser on from a page with no frame by the one script, its target escaped", () => {
		const next = 'https://idp.example/end?x="<y>"';
		const page = loggedOutPage({ next });
		expect(page.loads.frames).toEqual([]);
		expect(page.loads.scripts).toHaveLength(1);
		expect(page.html).toContain(`<script>${page.loads.scripts?.[0]}</script>`);
		expect(page.html).toContain('data-target="https://idp.example/end?x=&#34;&#60;y&#62;&#34;"');
		// The same script as the front-channel page's, so one hash allows both.
		expect(page.loads.scripts).toEqual(frontChannelPage(frames, { ...at, next })?.loads.scripts);
	});
});
