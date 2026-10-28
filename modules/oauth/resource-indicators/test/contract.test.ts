import { expect, it } from "vitest";
import { resourceRefusal } from "../src/contract.ts";

it("takes an absolute URI without a fragment, and tells why it refuses any other [rfc8707-2-a] [rfc8707-2-b]", () => {
	for (const taken of [
		"https://api.example",
		"https://api.example/v1?tenant=a",
		"urn:example:api",
		"http://127.0.0.1:8080/x",
	]) {
		expect(resourceRefusal(taken), taken).toBeUndefined();
	}
	for (const relative of ["api.example", "/v1", "//api.example/v1", "1https://api.example", ""]) {
		expect(resourceRefusal(relative), relative).toBe("resource is not an absolute URI");
	}
	for (const unwritten of [
		" https://api.example",
		"https://api.example/\tv1",
		"https://api.example\n",
	]) {
		expect(resourceRefusal(unwritten), JSON.stringify(unwritten)).toBe(
			"resource is not an absolute URI",
		);
	}
	for (const fragment of [
		"https://api.example#a",
		"https://api.example/v1#",
		"urn:example:api#x",
	]) {
		expect(resourceRefusal(fragment), fragment).toBe("resource carries a fragment");
	}
});
