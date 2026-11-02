import { expect, it } from "vitest";
import { parse, stringify } from "yaml";
import { swappedZod } from "../swap.ts";

const lockfile = stringify({
	lockfileVersion: "9.0",
	packages: {
		"@o3co/auth-provider-oauth@0.19.0": { resolution: { integrity: "sha512-OAUTH" } },
		"@x/grant@1.0.0": { resolution: { integrity: "sha512-GRANT" } },
		"jose@6.1.0": { resolution: { integrity: "sha512-JOSE" } },
		"zod@4.6.7": { resolution: { integrity: "sha512-ZOD" } },
	},
});

it("points zod at an unscoped package's tarball on the registry, with that package's integrity", () => {
	const swapped = swappedZod(lockfile, "https://registry.npmjs.org");
	if ("problem" in swapped) throw new Error(swapped.problem);
	expect(swapped.integrity).toBe("sha512-JOSE");
	const lock = parse(swapped.text);
	expect(lock.packages["zod@4.6.7"].resolution).toEqual({
		integrity: "sha512-JOSE",
		tarball: "https://registry.npmjs.org/jose/-/jose-6.1.0.tgz",
	});
	expect(lock.packages["jose@6.1.0"].resolution).toEqual({ integrity: "sha512-JOSE" });
});

it("says why where the lockfile holds no zod, or no other unscoped package from the registry", () => {
	const only = (packages: Record<string, unknown>) =>
		swappedZod(stringify({ lockfileVersion: "9.0", packages }), "https://registry.npmjs.org");
	expect(only({ "jose@6.1.0": { resolution: { integrity: "sha512-JOSE" } } })).toEqual({
		problem: "the lockfile holds no zod",
	});
	expect(
		only({
			"zod@4.6.7": { resolution: { integrity: "sha512-ZOD" } },
			"@x/grant@1.0.0": { resolution: { integrity: "sha512-GRANT" } },
			"left-pad@1.3.0": { resolution: { integrity: "sha512-PAD", tarball: "file:pad.tgz" } },
		}),
	).toEqual({ problem: "the lockfile holds no other package from the registry" });
});
