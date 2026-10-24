import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import { setUp } from "../src/new.ts";
import { commands } from "../src/recipes.ts";
import { composedBy } from "../src/selection.ts";

// It generates a recipe's app, which lists the workspace's packages through pnpm twice
// (`pnpm ls -r`, in create-app's project and in the combinations it reads): pnpm's own start takes
// 2.5 to 4 seconds on a busy machine, the most of the default five, so its tests are given the
// time that listing takes.
vi.setConfig({ testTimeout: 30_000 });

const workspace = join(import.meta.dirname, "..", "..", "..", "..");

describe("a recipe's set-up", () => {
	it("puts the MFA page recipe on Redis with a second factor required and a seal key, as before", async () => {
		const modules = await composedBy(commands["mfa-page"], workspace);
		const part = setUp({ modules });
		expect(part.modules).toEqual(modules);
		expect(part.store).toBe("pausable");
		expect(part.config?.mfa).toEqual({ mode: "required" });
		const key = (part.config?.seal?.current as { id: string; key: string }) ?? {};
		expect([key.id, Buffer.from(key.key, "base64").length]).toEqual(["recipes", 32]);
	});

	it("keeps a recipe composing no Redis, mfa or seal on a volatile store, adding no section of theirs", () => {
		const part = setUp({ modules: ["@mod/login-password", "@mod/users"] });
		expect(part.store).toBe("volatile");
		expect(part.config).toEqual({});
	});

	it("boots the file the recipe's reader writes, as written", () => {
		const localConf = "users { registered = [] }\n";
		expect(setUp({ modules: ["@mod/users"], localConf }).layer).toBe(localConf);
		expect(setUp({ modules: ["@mod/users"] }).layer).toBeUndefined();
	});
});
