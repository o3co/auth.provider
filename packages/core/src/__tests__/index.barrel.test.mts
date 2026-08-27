import { describe, expect, it } from "vitest";
import * as core from "../index.mjs";

describe("core barrel — Wave 1 AccessTokenDenylist exports", () => {
	it("re-exports createMemoryAccessTokenDenylist", () => {
		expect(typeof core.createMemoryAccessTokenDenylist).toBe("function");
	});
	it("re-exports createAccessTokenDenylistFactory", () => {
		expect(typeof core.createAccessTokenDenylistFactory).toBe("function");
	});
	it("re-exports registerBuiltinAccessTokenDenylists", () => {
		expect(typeof core.registerBuiltinAccessTokenDenylists).toBe("function");
	});
	it("re-exports memoryAccessTokenDenylistModule", () => {
		expect(core.memoryAccessTokenDenylistModule).toBeDefined();
		expect(typeof core.memoryAccessTokenDenylistModule).toBe("object");
	});
});

describe("core barrel — #282 signing defaults and secret entropy floor", () => {
	it("re-exports DEFAULT_SIGNING_ALGORITHM as an asymmetric algorithm", () => {
		// A composition root that hand-builds its keystore config reads this
		// rather than restating "EdDSA" and drifting from reference.conf.
		expect(core.DEFAULT_SIGNING_ALGORITHM).toBe("EdDSA");
		expect(core.DEFAULT_SIGNING_ALGORITHM).not.toBe("HS256");
	});

	it("re-exports the entropy floor helpers so consumers can apply the same check", () => {
		expect(core.MIN_SECRET_ENTROPY_BYTES).toBe(32);
		expect(typeof core.measureSecretEntropyBytes).toBe("function");
		expect(typeof core.assertSecretEntropy).toBe("function");
		expect(typeof core.describeWeakSecret).toBe("function");
	});
});
