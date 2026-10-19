import { clientAllowance } from "@mod/client-allowance";
import { type Clients, clients } from "@mod/clients";
import { type TargetRule, targets } from "@mod/grants";
import { type HttpRequest, type HttpResponse, jsonAnswer, type Route } from "@mod/http";
import { issuer } from "@mod/issuer";
import { type BuildContext, type Runtime, Unavailable } from "@mod/kernel";
import { authenticateClient, oauthError } from "@mod/token-endpoint";
import { userCodeFrom } from "../codes.ts";
import { deviceGrantType } from "../contract.ts";
import { type Device, toStored } from "../record.ts";
import type { Settings } from "../section.ts";
import { type DeviceStore, deviceStore, type UserCodes, userCodes } from "../store.ts";

export interface Authorizing {
	readonly clients: Clients;
	/** Asked, as for a grant that takes no audience, whether the request may ask one. */
	readonly targets: TargetRule;
	readonly devices: DeviceStore;
	readonly userCodes: UserCodes;
	readonly issuer: string;
	readonly runtime: Runtime;
	readonly settings: Settings;
}

/** A fresh user code may meet one in use; it is drawn again a few times before giving up. */
const draws = 5;

function withUserCode(page: string, userCode: string): string {
	const url = new URL(page);
	url.searchParams.set("user_code", userCode);
	return url.href;
}

/** RFC 8628 §3.1–3.2: a device asks for codes, as an authenticated client allowed this grant. */
export function authorizationWith(a: Authorizing): Pick<Route, "handle" | "unavailable"> {
	const lifetimeMs = a.settings["code-lifetime"] * 1000;
	// Kept as long again past its end, so a device still polling is told its code expired.
	const keptMs = lifetimeMs * 2;
	const keepUserCode = async (name: string): Promise<string> => {
		for (let i = 0; i < draws; i++) {
			const drawn = userCodeFrom(a.runtime.random.bytes);
			if ((await a.userCodes.save(drawn, name, keptMs)) === "created") return drawn;
		}
		throw new Unavailable("device-grant");
	};
	const answer = async (request: HttpRequest): Promise<HttpResponse> => {
		const authenticated = await authenticateClient(a.clients, request);
		if (authenticated.kind === "refused") return authenticated.response;
		const { client } = authenticated;
		if (request.form.repeated().length > 0) {
			return oauthError(400, "invalid_request", "repeated parameter");
		}
		if (!clientAllowance.allowsGrant(client, deviceGrantType))
			return oauthError(400, "unauthorized_client");
		const untargeted = a.targets.untargeted?.({ param: (name) => request.form.single(name) });
		if (untargeted) return oauthError(400, untargeted.error, untargeted.description);
		const allowed = clientAllowance.allowedIssuance(client, request.form.single("scope"), a.issuer);
		if (allowed.kind === "error") return oauthError(400, allowed.error, allowed.description);
		const deviceCode = Buffer.from(a.runtime.random.bytes(32)).toString("base64url");
		const name = a.devices.nameOf(deviceCode);
		const now = a.runtime.clock.now();
		const device: Device = {
			format: 2,
			clientId: client.id,
			scope: allowed.scope,
			audience: allowed.audience,
			expiresAt: now + lifetimeMs,
			intervalMs: a.settings.interval * 1000,
			state: "pending",
		};
		// A name from 32 fresh random bytes cannot exist yet; if it does, the store cannot be trusted to tell.
		if ((await a.devices.save(name, toStored(device), keptMs)) !== "created") {
			throw new Unavailable("device-grant");
		}
		const userCode = await keepUserCode(name);
		const page = a.settings["verification-uri"];
		return jsonAnswer(200, {
			device_code: deviceCode,
			user_code: userCode,
			verification_uri: page,
			...(a.settings["complete-uri"]
				? { verification_uri_complete: withUserCode(page, userCode) }
				: {}),
			expires_in: a.settings["code-lifetime"],
			interval: a.settings.interval,
		});
	};
	return { handle: answer, unavailable: { response: oauthError(503, "temporarily_unavailable") } };
}

/** The handler over the contracts the assembly gives. */
export const authorizationOver = async (c: BuildContext<Settings>) =>
	authorizationWith({
		clients: await c.get(clients),
		targets: await c.get(targets),
		devices: await c.get(deviceStore),
		userCodes: await c.get(userCodes),
		issuer: (await c.get(issuer)).url,
		runtime: c,
		settings: c.section,
	});
