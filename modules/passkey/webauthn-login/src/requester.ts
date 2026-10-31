import type { Requester } from "@mod/passkeys";

/** The client a challenge is made for, and redeemed by, as passkeys tells this module's own apart. */
export const requesterFor = (clientId: string): Requester => ({
	by: "webauthn-login",
	id: clientId,
});
