import type { z } from "zod";
import type { section } from "./section.ts";

export type AuthorizeSettings = z.input<typeof section>;

export function authorizeConfig(settings: Partial<AuthorizeSettings> = {}) {
	return { authorize: { "login-page": "https://as.example/login", ...settings } };
}
