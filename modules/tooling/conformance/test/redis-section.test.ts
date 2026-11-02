import { describe, expect, it } from "vitest";
import { sceneRedis } from "../src/drivers/app.ts";

describe("the Redis a scene's app is given", () => {
	it("waits on a command as long as a busy machine's fsync takes, its server still fsyncing every write", () => {
		expect(sceneRedis("redis://127.0.0.1:6400", false)).toEqual({
			url: "redis://127.0.0.1:6400",
			replication: "none",
			"command-timeout": "5s",
		});
	});

	it("keeps the default wait where the scene pauses the store, so its unavailable answers come as an app's would", () => {
		expect(sceneRedis("redis://127.0.0.1:6400", true)).toEqual({
			url: "redis://127.0.0.1:6400",
			replication: "none",
		});
	});
});
