import { assemble, contract, defineModule, isUnavailable, kernelConfig } from "@mod/kernel";
import { quietRuntime, takesUnused } from "@mod/kernel/testing";
import { type FactorKind, factorKinds, type Opened, type Verified } from "@mod/mfa-extensions";
import { type AttributesAnswer, subjectAttributes } from "@mod/subject-attributes";
import webauthnModule from "@mod/webauthn/module";
import {
	softwareAuthenticator,
	type Twist,
	testOrigin,
	webauthnConfig,
} from "@mod/webauthn/testing";
import { beforeEach, expect, it } from "vitest";
import kindModule from "../src/module.ts";

/** How far the kernel's clock runs ahead of the host's; it goes back after each test. */
let shift = 0;
const runtime = quietRuntime({ clock: { now: () => Date.now() + shift } });
const kinds = contract<readonly FactorKind[]>("kinds");
const browser = { origin: testOrigin };
/** What subject-attributes answers, by subject; unknown for any other. */
const attributes = new Map<string, AttributesAnswer>();
beforeEach(() => {
	attributes.clear();
	shift = 0;
});
const known = (values: Record<string, unknown>): AttributesAnswer => ({
	kind: "known",
	vouched: true,
	attributes: values,
});
const attributesStandIn = defineModule({ name: "subject-attributes", takes: [] }, (m) => [
	m.provide(subjectAttributes).by(() => ({
		of: async (subject) => attributes.get(subject) ?? { kind: "unknown" },
	})),
]);
const credentialIdOf = (factor: Opened) => (factor.state as { id: string }).id;
const handleOf = (secret: string) => (JSON.parse(secret) as { handle: string }).handle;

/** The kind's composition: the kind, webauthn, a stand-in for the attributes, a reader of the kinds. */
const composition = (settings: Record<string, unknown> = {}) => ({
	modules: [
		attributesStandIn,
		webauthnModule,
		kindModule,
		defineModule({ name: "reader", takes: [factorKinds] }, (m) => [
			m.provide(kinds).by((c) => c.collect(factorKinds)),
		]),
	],
	config: {
		...kernelConfig(),
		...webauthnConfig(),
		"mfa-webauthn": settings,
	},
	runtime,
});

async function boot(settings: Record<string, unknown> = {}) {
	const app = await assemble(composition(settings));
	return app.get(kinds)[0] as FactorKind;
}

it("takes all it names", async () => {
	expect(await takesUnused(composition())).toEqual({});
});

/** Binds a credential of the authenticator as a binding's first proof does. */
async function bound(
	kind: FactorKind,
	authenticator: ReturnType<typeof softwareAuthenticator>,
	subject = "alice",
	twist: Twist = {},
) {
	const enrolled = await kind.enroll(subject, []);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	const response = authenticator.create(enrolled.show as never, browser, twist);
	const proved = await kind.verify(enrolled.secret, null, JSON.stringify(response));
	if (proved.kind !== "valid") throw new Error(proved.kind);
	return {
		factor: { secret: enrolled.secret, state: proved.state },
		amr: proved.amr,
		show: enrolled.show,
	};
}

/** The assertion the authenticator gives to the factor's challenge, and what the challenge kept. */
async function asserted(
	kind: FactorKind,
	factor: Opened,
	authenticator: ReturnType<typeof softwareAuthenticator>,
	twist: Twist = {},
	latest = Date.now() + 600_000,
) {
	const sent = await kind.challenge?.("alice", factor, latest);
	if (sent?.kind !== "sent") throw new Error("not sent");
	return {
		proof: JSON.stringify(authenticator.get(sent.show as never, browser, twist)),
		kept: sent.kept,
		show: sent.show,
	};
}

it("declares a counting second factor that guessing cannot beat", async () => {
	expect(await boot()).toMatchObject({
		kind: "webauthn",
		amr: ["pop"],
		addsSecondFactor: true,
		guessable: false,
		counts: true,
	});
});

it("binds a credential that need not be discoverable, under the name the operator gives, and proves it", async () => {
	const kind = await boot({ "display-name": "Example" });
	const authenticator = softwareAuthenticator({ discoverable: false });
	const { factor, amr, show } = await bound(kind, authenticator);
	expect(show).toMatchObject({
		user: { name: "Example", displayName: "Example" },
		authenticatorSelection: { residentKey: "discouraged", userVerification: "preferred" },
	});
	expect(amr).toEqual(["pop"]);
	const { proof, kept, show: request } = await asserted(kind, factor, authenticator);
	expect(request).toMatchObject({
		allowCredentials: [{ id: credentialIdOf(factor) }],
	});
	expect(await kind.verify(factor.secret, factor.state, proof, kept)).toMatchObject({
		kind: "valid",
		amr: ["pop"],
	});
});

it("shows the authenticator the subject's name, never its email, else the name the operator gives", async () => {
	const kind = await boot({ "display-name": "Example" });
	const shown = async (subject: string) => {
		const enrolled = await kind.enroll(subject, []);
		if (!("secret" in enrolled)) throw new Error("not enrolled");
		return (enrolled.show as { user: { name: string; displayName: string } }).user;
	};
	attributes.set("ann", known({ name: "Ann Lee", email: "ann@example.com" }));
	expect(await shown("ann")).toMatchObject({ name: "Ann Lee", displayName: "Ann Lee" });
	attributes.set("bob", known({ email: "bob@example.com" }));
	const cases: Record<string, unknown> = {
		"email only": undefined,
		"not text": 7,
		empty: "",
		"past 64 code points": "d".repeat(65),
		"a control character": "Ann\u0007",
		"a format character": "Ann\u202e",
		"a lone surrogate": "Ann\ud800",
	};
	for (const [name, value] of Object.entries(cases)) {
		attributes.set(
			"cal",
			known(value === undefined ? { email: "cal@example.com" } : { name: value }),
		);
		expect(await shown("cal"), name).toMatchObject({ name: "Example" });
	}
	attributes.set("dee", known({ name: "\u{1F600}".repeat(64) }));
	expect((await shown("dee")).name).toBe("\u{1F600}".repeat(64));
	expect(await shown("eve")).toMatchObject({ name: "Example" });
});

it("names no one by default, and refuses to boot on a name it cannot show", async () => {
	attributes.set("ann", known({}));
	const enrolled = await (await boot()).enroll("ann", []);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	expect(enrolled.show).toMatchObject({ user: { name: "Account" } });
	for (const name of ["", "x".repeat(65), "Ex\nample"]) {
		await expect(boot({ "display-name": name }), JSON.stringify(name)).rejects.toThrow();
	}
});

it("asks the user verification the operator sets", async () => {
	const enrolled = await (await boot({ "user-verification": "required" })).enroll("alice", []);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	expect(enrolled.show).toMatchObject({ authenticatorSelection: { userVerification: "required" } });
});

it("names a credential that may be backed up pop too, at binding and at every assertion: nothing tells how a key is kept", async () => {
	const kind = await boot();
	const authenticator = softwareAuthenticator({ backupEligible: true });
	const { factor, amr } = await bound(kind, authenticator);
	expect(amr).toEqual(["pop"]);
	const { proof, kept } = await asserted(kind, factor, authenticator);
	expect(await kind.verify(factor.secret, factor.state, proof, kept)).toMatchObject({
		amr: ["pop"],
	});
});

it("keeps one user handle for the subject's factors, excludes the credentials it holds, and tells apart only its own duplicates", async () => {
	const kind = await boot();
	const authenticator = softwareAuthenticator();
	const first = await bound(kind, authenticator);
	const second = await kind.enroll("alice", [first.factor]);
	if (!("secret" in second)) throw new Error("not enrolled");
	expect(handleOf(second.secret)).toBe(handleOf(first.factor.secret));
	expect(second.show).toMatchObject({ excludeCredentials: [{ id: credentialIdOf(first.factor) }] });
	const again = { secret: second.secret, state: first.factor.state };
	expect(kind.uniqueSecret?.(again)).toBe(kind.uniqueSecret?.(first.factor));
	const elsewhere = await bound(kind, softwareAuthenticator());
	expect(handleOf(elsewhere.factor.secret)).not.toBe(handleOf(first.factor.secret));
	expect(
		kind.uniqueSecret?.({ secret: elsewhere.factor.secret, state: first.factor.state }),
	).not.toBe(kind.uniqueSecret?.(first.factor));
});

it("keeps two subjects' factors apart under one credential id: each proves only its own", async () => {
	const kind = await boot();
	const alices = softwareAuthenticator();
	const bobs = softwareAuthenticator();
	const alice = await bound(kind, alices);
	const bob = await bound(kind, bobs, "bob", { credentialId: credentialIdOf(alice.factor) });
	expect(credentialIdOf(bob.factor)).toBe(credentialIdOf(alice.factor));
	expect(kind.uniqueSecret?.(bob.factor)).not.toBe(kind.uniqueSecret?.(alice.factor));
	const verified = async (factor: Opened, by: ReturnType<typeof softwareAuthenticator>) => {
		const { proof, kept } = await asserted(kind, factor, by, { overlook: true });
		return (await kind.verify(factor.secret, factor.state, proof, kept)).kind;
	};
	expect(await verified(alice.factor, alices)).toBe("valid");
	expect(await verified(bob.factor, bobs)).toBe("valid");
	expect(await verified(alice.factor, bobs)).toBe("invalid");
	expect(await verified(bob.factor, alices)).toBe("invalid");
});

it("takes an assertion whose count did not go up as replayed, and any other refusal as invalid", async () => {
	const kind = await boot();
	const authenticator = softwareAuthenticator();
	const { factor } = await bound(kind, authenticator);
	const first = await asserted(kind, factor, authenticator);
	const proved = await kind.verify(factor.secret, factor.state, first.proof, first.kept);
	if (proved.kind !== "valid") throw new Error(proved.kind);
	const behind = await asserted(kind, { ...factor, state: proved.state }, authenticator, {
		counter: 0,
	});
	expect(await kind.verify(factor.secret, proved.state, behind.proof, behind.kept)).toEqual({
		kind: "replayed",
	});
	const current = { ...factor, state: proved.state };
	const fresh = await asserted(kind, current, authenticator);
	/** An assertion by another authenticator to the factor's challenge, its credential not the one asked for. */
	const foreign = async () => {
		const other = softwareAuthenticator();
		await bound(kind, other);
		const sent = await asserted(kind, current, other, { overlook: true });
		return kind.verify(factor.secret, current.state, sent.proof, sent.kept);
	};
	// One at a time, so a case that throws fails under its own name.
	const cases: Record<string, () => Promise<Verified>> = {
		"another challenge kept": () =>
			kind.verify(
				factor.secret,
				current.state,
				fresh.proof,
				JSON.stringify({ challenge: "b3RoZXI", until: Date.now() + 60_000 }),
			),
		"proof not JSON": () => kind.verify(factor.secret, current.state, "not json", fresh.kept),
		"no challenge kept": () => kind.verify(factor.secret, current.state, fresh.proof),
		"another user handle": async () => {
			const other = await asserted(kind, current, authenticator, { userHandle: "b3RoZXI" });
			return kind.verify(factor.secret, current.state, other.proof, other.kept);
		},
		"another credential": foreign,
	};
	for (const [name, verified] of Object.entries(cases)) {
		expect(await verified(), name).toEqual({ kind: "invalid" });
	}
});

it("fails unavailable on a factor whose credential does not read, as a store fault, sending nothing", async () => {
	const kind = await boot();
	const broken = { secret: "{}", state: { id: 7 } };
	await expect(kind.challenge?.("alice", broken, Date.now())).rejects.toSatisfy(isUnavailable);
	await expect(kind.verify(broken.secret, broken.state, "{}", "kept")).rejects.toSatisfy(
		isUnavailable,
	);
});

it("fails unavailable on a pending secret or a kept challenge that does not read, as a store fault", async () => {
	const kind = await boot();
	const authenticator = softwareAuthenticator();
	const { factor } = await bound(kind, authenticator);
	const { proof, kept } = await asserted(kind, factor, authenticator);
	const { challenge, handle } = JSON.parse(factor.secret) as { challenge: string; handle: string };
	const cases: Record<string, () => Promise<Verified>> = {
		"secret not JSON": () => kind.verify("not a secret", null, proof),
		"secret with no end": () => kind.verify(JSON.stringify({ handle, challenge }), null, proof),
		"kept not JSON": () => kind.verify(factor.secret, factor.state, proof, "not kept"),
		"kept with no end": () =>
			kind.verify(factor.secret, factor.state, proof, JSON.stringify({ challenge: "x" })),
	};
	for (const [name, verified] of Object.entries(cases)) {
		await expect(verified(), name).rejects.toSatisfy(isUnavailable);
	}
	expect((await kind.verify(factor.secret, factor.state, proof, kept)).kind).toBe("valid");
});

it("takes an answer only before its challenge's end: webauthn's own, or the caller's when earlier", async () => {
	const kind = await boot();
	const authenticator = softwareAuthenticator();
	const { factor } = await bound(kind, authenticator);
	const at = async (latest: number, after: number) => {
		const { proof, kept } = await asserted(kind, factor, authenticator, {}, latest);
		shift += after;
		const verified = await kind.verify(factor.secret, factor.state, proof, kept);
		shift -= after;
		return verified.kind;
	};
	const now = Date.now();
	expect(await at(now + 600_000, 119_000)).toBe("valid");
	expect(await at(now + 600_000, 121_000)).toBe("invalid");
	expect(await at(now + 60_000, 61_000)).toBe("invalid");
});

it("binds only before the creation's end", async () => {
	const kind = await boot();
	const enrolled = await kind.enroll("alice", []);
	if (!("secret" in enrolled)) throw new Error("not enrolled");
	const response = softwareAuthenticator().create(enrolled.show as never, browser);
	shift += 121_000;
	expect((await kind.verify(enrolled.secret, null, JSON.stringify(response))).kind).toBe("invalid");
});
