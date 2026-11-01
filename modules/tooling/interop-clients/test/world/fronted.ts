import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type AreaScene,
	area,
	areaTarget,
	onNew,
	type Started,
	type StartOptions,
} from "@mod/conformance";
import { selfSigned, startFront } from "@mod/conformance-front";

/** The address the front tells the app the libraries send from: not loopback, which is its trusted proxy. */
export const sender = "198.51.100.30";

/** What the harness asks of the app beyond the areas' scenes, for the modules it composes. */
export const harnessArea = area<{ readonly outboundProxy?: string }>("interop-clients");
const perSource = 1000;
// A nonce asked at the token endpoint and at the resources alike, so each library's retry is met (RFC 9449 §8, §9).
const dpopNonce = { required: "as+rs", secret: randomBytes(32).toString("base64") };
onNew(harnessArea, (part, __, modules) => {
	const where = (module: string, section: Record<string, Record<string, unknown>>) =>
		modules.includes(module) ? section : {};
	return {
		config: {
			// Limits one source's whole run can meet; the most attempts the login takes in a window.
			...where("@mod/authorize", { authorize: { requests: perSource } }),
			...where("@mod/token-endpoint", { "token-endpoint": { requests: perSource } }),
			...where("@mod/token-control", { "token-control": { requests: perSource } }),
			...where("@mod/login-password", { "login-password": { attempts: 100, window: "1m" } }),
			...where("@mod/dpop", { dpop: { nonce: dpopNonce } }),
			// The https parties the app reaches by name, through a tunnel to this machine.
			...(part.outboundProxy
				? where("@mod/outbound", { outbound: { proxy: part.outboundProxy } })
				: {}),
		},
	};
});

/** An RS256 signing key of this run's own, the algorithm every library takes for an ID token. */
export function signing() {
	const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return {
		kid: `interop-${Date.now().toString(36)}`,
		alg: "RS256" as const,
		privatePem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

/** A running app behind its https front: the front's origin is its issuer. */
export interface Fronted {
	readonly origin: string;
	/** The front's certificate, as PEM, which every adapter trusts and nothing else. */
	readonly ca: string;
	/** Where the app itself listens, for the driver's own requests. */
	base(): string;
	/** Each token request a library sent through the front, in order. */
	readonly tokenRequests: readonly URLSearchParams[];
	stop(): Promise<void>;
}

/**
 * Starts the front, then the app of `sceneAt(origin)` (by `start`, the conformance target's unless
 * given), its files under `under`; where the app does not start, the front is closed and the files
 * removed before the failure, with what the app told, is thrown.
 */
export async function fronted(
	sceneAt: (origin: string) => AreaScene,
	given: {
		readonly start?: (scene: AreaScene, options?: StartOptions) => Promise<Started>;
		readonly under?: string;
		/** The header the front forwards a client's certificate in, as a deployment's proxy does. */
		readonly clientCertificateHeader?: string;
		/** Certificates (PEM files) the app trusts, for the https parties it reaches. */
		readonly trustedCertificates?: readonly string[];
		/** The proxy the app reaches its https parties through. */
		readonly outboundProxy?: string;
	} = {},
): Promise<Fronted> {
	const start =
		given.start ??
		((scene: AreaScene, options?: StartOptions) => areaTarget().start(scene, options));
	const dir = await mkdtemp(join(given.under ?? tmpdir(), "interop-clients-"));
	const tls = await selfSigned("127.0.0.1", dir);
	let base = "";
	const tokenRequests: URLSearchParams[] = [];
	const front = await startFront({
		upstream: () => base,
		publicHost: "127.0.0.1",
		listen: "127.0.0.1",
		tls,
		sender,
		...(given.clientCertificateHeader
			? { clientCertificate: { header: given.clientCertificateHeader } }
			: {}),
		answered: (request) => {
			if (request.method === "POST" && request.url.pathname === "/oauth/token")
				tokenRequests.push(new URLSearchParams(request.body.toString()));
		},
	});
	const cleared = async () => {
		await front.stop();
		await rm(dir, { recursive: true, force: true });
	};
	const scene = sceneAt(front.origin);
	const harness = given.outboundProxy ? { outboundProxy: given.outboundProxy } : {};
	const options = given.trustedCertificates
		? { trustedCertificates: given.trustedCertificates }
		: {};
	const running = await start(
		{ ...scene, parts: { ...scene.parts, [harnessArea.name]: harness } },
		options,
	).catch(async (failure: unknown) => {
		await cleared();
		throw failure;
	});
	if (running.kind !== "running") {
		await cleared();
		throw new Error(`the app refused to start:\n${running.output}`);
	}
	base = running.baseUrl;
	return {
		origin: front.origin,
		ca: tls.cert,
		base: () => base,
		tokenRequests,
		async stop() {
			await running.stop();
			await cleared();
		},
	};
}
