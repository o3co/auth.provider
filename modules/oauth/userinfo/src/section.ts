import { z } from "zod";

/** `issuer-audience`, no longer read: taken while a deployment still states it, then gone. */
export const section = z.strictObject({
	"issuer-audience": z
		.enum(["off", "adding", "on"])
		.optional()
		.describe("No longer read: userinfo tells its own tokens by the openid scope."),
});
