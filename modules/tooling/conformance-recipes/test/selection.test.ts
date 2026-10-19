import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { commands } from "../src/recipes.ts";
import { composedBy } from "../src/selection.ts";

const workspace = join(import.meta.dirname, "..", "..", "..", "..");

describe("the MFA page recipe's command", () => {
	it("composes password login, TOTP alone, an HTTP ledger and Redis, and no other factor or witness", async () => {
		const modules = await composedBy(commands["mfa-page"], workspace);
		for (const name of ["@mod/login-password", "@mod/mfa-totp", "@mod/users-http", "@mod/redis"]) {
			expect(modules, name).toContain(name);
		}
		for (const name of [
			"@mod/mfa-recovery",
			"@mod/mfa-email",
			"@mod/mfa-witness-http",
			"@mod/mail-smtp",
		]) {
			expect(modules, name).not.toContain(name);
		}
	});
});
