import { expect, it } from "vitest";
import { installArguments } from "../image.ts";

it("installs in the base stage as the runner's own user, so what it writes is the runner's to remove", () => {
	const args = installArguments({
		mounts: ["/s/deps/app:/app", "/s/tarballs:/tarballs:ro", "/s/cache:/cache"],
		base: "run:base",
		user: "1001:121",
	});
	expect(args).toEqual([
		"-v",
		"/s/deps/app:/app",
		"-v",
		"/s/tarballs:/tarballs:ro",
		"-v",
		"/s/cache:/cache",
		"--user",
		"1001:121",
		"-e",
		"HOME=/cache/home",
		"-e",
		"COREPACK_HOME=/cache/corepack",
		"-e",
		"COREPACK_ENABLE_DOWNLOAD_PROMPT=0",
		"run:base",
		"pnpm",
		"install",
		"--prod",
		"--no-frozen-lockfile",
		"--store-dir",
		"/cache/store",
	]);
});
