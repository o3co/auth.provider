import { describe, expect, it } from "vitest";
import { clientSection } from "../routes.ts";

describe("the client metadata section", () => {
	const takes = (uri: string) => {
		const read = clientSection.schema["~standard"].validate({ "post-logout-redirect-uris": [uri] });
		if (read instanceof Promise) throw new Error("read asynchronously");
		return read.issues === undefined;
	};

	it("takes as an upstream logout's return only a URI a client may register to be sent back to", () => {
		for (const uri of [
			"https://app.example/back",
			"http://127.0.0.1:8080/back",
			"com.example.app:/back",
		]) {
			expect(takes(uri), uri).toBe(true);
		}
		for (const uri of [
			"javascript:alert(1)",
			"http://app.example/back",
			"https://app.example/back#frag",
			"https://user:pw@app.example/back",
			"https://app.example/back?state=x",
			"not a uri",
		]) {
			expect(takes(uri), uri).toBe(false);
		}
	});
});
