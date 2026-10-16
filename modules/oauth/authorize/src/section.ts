import { urlSetting } from "@mod/url-setting";
import { z } from "zod";

export const section = z.strictObject({
	"login-page": urlSetting({ schemes: ["https"] }),
	/** Where a session that falls short of an acr is sent to raise its authentication. */
	"step-up-page": urlSetting({ schemes: ["https"] }).optional(),
	/** Whether every request names `openid` in its own scope (`dual` also serves plain OAuth clients). */
	"oidc-mode": z.enum(["oidc-required", "dual"]).default("oidc-required"),
	/** Requests allowed per source in each window, over both methods. */
	requests: z.number().int().min(1).max(100_000).default(60),
	"window-seconds": z.number().int().min(1).max(86_400).default(60),
});

export type Settings = z.output<typeof section>;
