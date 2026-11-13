# Recipe: a grant of your own, in your own package

The module cards are the source of truth. Where this page and a card disagree, the card wins. This page orders the steps and points to the cards; the package, the code, the commands and the exchange below are built and run against the published packages before each release, so they do not go stale.

It writes an OAuth grant as an npm package outside this repository, modelled on the client credentials grant (`client-credentials`), and has the generator compose it into an app.

## The package

Depend on the published packages your module imports, all at the one version of the release you run: every package of a release shares it. Keep them as peers, so the app installs one copy of each. The kernel finds contracts and extension points by the object itself, never by name, so a second copy of a package is a different contract, and your grant would reach no token endpoint (the `kernel` card).

Export the module the app imports at `./module`, as every module of the provider does: the generator composes your package by importing it from there ([packages outside the release](outside-modules.md#export-the-module)). Declare it in `authProvider`, as the generator reads it: this one is a feature, needing the modules its code takes and contributes to ([declare it](outside-modules.md#declare-it)).

<!-- generated:package-json -->
```json
{
	"name": "@example/example-grant",
	"version": "1.0.0",
	"type": "module",
	"exports": {
		"./module": {
			"types": "./module.d.ts",
			"default": "./module.js"
		}
	},
	"scripts": {
		"build": "tsc -p tsconfig.json"
	},
	"peerDependencies": {
		"@o3co/auth-provider-foundation": "<version>",
		"@o3co/auth-provider-identity": "<version>",
		"@o3co/auth-provider-oauth": "<version>",
		"zod": "^4.6.0"
	},
	"authProvider": {
		"format": 1,
		"kind": "feature",
		"needs": [
			"@mod/client-allowance",
			"@mod/grants",
			"@mod/issuer",
			"@mod/tokens"
		]
	}
}
```
<!-- end generated -->

## The grant

A grant is a contribution to the `grants` extension point (the `grants` card). This one gives a confidential client a token for itself, within what its allowance lets it ask, as the client credentials grant does (the `client-credentials` card). `readsAmbient` says the grant reads nothing the request carries beside its parameters; a grant that reads the session's cookie must say `cookie` and check the request's origin itself. The module's head declares `takes`, the handles its factories take from other modules: here `issuer` and `tokens`, the contracts its factory gets (the `kernel` card). A module with a section declares it there too, and takes `zod` as a peer ([packages outside the release](outside-modules.md#take-the-release-and-zod-as-peers)). Boot refuses a module that declares none; one that takes nothing declares `[]`.

<!-- generated:module -->
```ts
import { defineModule, setting } from "@o3co/auth-provider-foundation/kernel";
import { clientAllowance } from "@o3co/auth-provider-oauth/client-allowance";
import { type Grant, grants } from "@o3co/auth-provider-oauth/grants";
import { issuer } from "@o3co/auth-provider-oauth/issuer";
import { lifetimeSecondsRange, tokens } from "@o3co/auth-provider-oauth/tokens";
import { z } from "zod";

/** The grant type a client names; a URI, as RFC 6749 asks of an extension grant. */
const grantType = "urn:example:params:oauth:grant-type:example";

/** The longest an access token of this grant may live, the operator's to lower. */
const section = z.strictObject({
	"access-token-ceiling": setting
		.duration("s")
		.pipe(z.number().int().min(lifetimeSecondsRange.min).max(lifetimeSecondsRange.max))
		.prefault("1h"),
});

/** A confidential client's token for itself, within what its allowance lets it ask. */
const example = (issuerUrl: string): Grant => ({
	grantType,
	readsAmbient: "none",
	handle: async ({ client, param, issue }) => {
		if (client.kind !== "confidential") return { kind: "error", error: "unauthorized_client" };
		const allowed = clientAllowance.allowedIssuance(client, param("scope"), issuerUrl);
		if (allowed.kind === "error") return allowed;
		const { scope, audience } = allowed;
		const issued = await issue({ subject: client.id, issuedTo: client.id, audience, scope });
		if (issued.kind === "refused") return issued;
		const { token, tokenType, expiresIn } = issued.access;
		return {
			kind: "issued",
			body: {
				access_token: token,
				token_type: tokenType,
				expires_in: expiresIn,
				scope: scope.join(" "),
			},
		};
	},
});

// Safe on many instances: it keeps nothing across requests.
export default defineModule(
	{ name: "example-grant", section, replicaSafe: true, takes: [issuer, tokens] },
	(m) => [
		m.contribute(grants).by(async (c) => {
			// Read at build time: the lifetime `issue` applies where this grant gives none is fixed by now.
			const lifetime = (await c.get(tokens)).accessTokenLifetimeSeconds();
			if (lifetime > c.section["access-token-ceiling"]) {
				// Settings by their keys, never their values.
				return c.refuse(
					"example-grant.access-token-ceiling",
					"tokens.access-token-lifetime is over it: lower that, or raise this",
				);
			}
			return example((await c.get(issuer)).url);
		}),
	],
);
```
<!-- end generated -->

This grant holds its tokens to a lifetime ceiling, a setting of its own. `tokens` tells the lifetime `issue` applies where a grant gives none, `accessTokenLifetimeSeconds()`, fixed when `tokens` is built, so a check at build time stays true: read it there, and refuse boot above your ceiling with `c.refuse`, naming both settings by their keys, never their values. That is not the longest life any token may have, and the check does not reach tokens already issued, or instances still on other settings. A lifetime your grant gives at one issuance, `lifetimeSeconds` in `issue`'s limits, is your grant's own to hold to its ceiling: `tokens` does not check it against one. It runs from 2 to 86400 whole seconds, and anything else, 1 among it, throws at the request: check at boot a value you will give against `lifetimeSecondsRange`, which `tokens` exports, as this grant's ceiling does.

If your grant calls another server, take `outbound`'s contract and send the request through it (the `outbound` card), so the operator's destination policy and limits apply. The guard's rule that holds the provider's own packages to that (G26, and the `network` declaration in a package manifest) reads only the provider's repository: in your package, nothing checks it but you.

## Add it to the app

Publish your package to a registry, npm's or one of your own, under a name of your own: `@example/example-grant` here stands for it. Install the package with pnpm into a project of your own: the generator reads your package from that project, never from a registry. Generate the app from outside it, naming the package `npm:<name>` and the project `--outside-from`, then check the app's lockfile before installing it ([composing a package outside the release](outside-modules.md#composing-a-package-outside-the-release)):

<!-- generated:command -->
```sh
mkdir outside && cd outside
echo '{ "private": true }' > package.json
pnpm add @example/example-grant@1.0.0
cd ..
npx @o3co/create-auth-provider my-provider --pattern simple-web --add npm:@example/example-grant --outside-from outside
cd my-provider
pnpm install --lockfile-only
node scripts/check-outside.mjs
pnpm install --frozen-lockfile --ignore-scripts
```
<!-- end generated -->

The generator composes your module into the app's `src/main.ts` beside the release's, and records your package and its integrity in `outside-modules.json`; `scripts/check-outside.mjs` holds the lockfile to that record. Commit the lockfile once the check passes. Such an app runs its files with node, not through its scripts ([run the app by its files](outside-modules.md#run-the-app-by-its-files)).

## Allow it for a client

The token endpoint answers `unauthorized_client` to a client whose `client-allowance` does not list the grant type (the `client-allowance` card). Register the client with the grant and the scopes it may ask:

<!-- generated:client -->
```hocon
clients.registered = [{
  "id": "example-client",
  "kind": "confidential",
  "method": "client_secret_basic",
  "sections": {
    "client-secret": {
      "hash": "<a bcrypt or scrypt hash of its secret>"
    },
    "client-allowance": {
      "grants": [
        "urn:example:params:oauth:grant-type:example"
      ],
      "scopes": [
        "example"
      ]
    }
  }
}]
```
<!-- end generated -->

## Ask for a token

<!-- generated:request -->
```http
POST /oauth/token
content-type: application/x-www-form-urlencoded
authorization: Basic <base64 of example-client:its-secret>

grant_type=urn%3Aexample%3Aparams%3Aoauth%3Agrant-type%3Aexample&scope=example
```

```http
200
content-type: application/json

{
  "access_token": "<access_token>",
  "token_type": "Bearer",
  "expires_in": "<seconds>",
  "scope": "example"
}
```
<!-- end generated -->

The endpoint names your grant type in the discovery document's `grant_types_supported`, as it does each grant contributed.

## Add claims to the token

A grant may add claims of its own to the access token it issues: put them in the `claims` of the grant it hands `issue`.

```ts
const issued = await input.issue({
	subject,
	issuedTo: input.client.id,
	audience,
	scope,
	claims: { "https://example.com/claims/contract": contractId },
});
```

- Names are 1 to 255 code points, well formed, with no space or control character; a collision-resistant name, a URI you control, is safest. A reserved name (what `tokens` writes, the names a specification gives a meaning, such as `nbf`, `roles` or `email`, and `__proto__`, `constructor`, `prototype` and `toJSON` at any depth) is refused.
- Values are plain JSON: strings, finite numbers, booleans, arrays and plain objects, at most 8 deep and 4 KiB in all. Anything else is refused, a null at any depth among it: leave the member out. The `added-claims` module's card states every rule and limit.
- A refusal is a `TypeError`: the grant's mistake, answered as an error, not audited as a refused issuance.
- The token's issuance policies see the claims, and `verifyAccess` reads them back (`grant.claims`). The audit's `token.issued` names them, never their values.
- A refresh or an exchange issues no added claim. Do not use one for a restriction that must hold on such a token.
- The resource server cannot tell an added claim from one the provider wrote: composing your grant entrusts it with what its tokens say.
