import { z } from "zod";

/** Unset or another value: the choice an operator makes, each step taken once every host has taken the last. */
const chooseOne =
	"set `off` while any host runs a release before 0.19, which reads every aud as the grant's, `adding` once every host runs 0.19, then `on` once every access token issued before `adding` has expired; `adding`, then `off`, before going back";

export const section = z.strictObject({
	"issuer-audience": z
		.enum(["off", "adding", "on"], { error: chooseOne })
		.describe(
			"off adds the issuer to no token's audience and requires it of none; adding names the issuer in an openid token's aud, but does not yet require it; on names it and refuses at userinfo an openid token whose aud does not.",
		),
});

export type Settings = z.output<typeof section>;
