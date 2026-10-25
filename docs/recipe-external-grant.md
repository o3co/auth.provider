# Recipe: a grant of your own, in your own package

The module cards are the source of truth. Where this page and a card disagree, the card wins. This page orders the steps and points to the cards; the package, the code and the exchange below are built and run against the published packages before each release, so they do not go stale.

It writes an OAuth grant as an npm package outside this repository, modelled on the client credentials grant (`client-credentials`), and adds it to an app the generator made.

## The package

Depend on the published packages your module imports, all at the one version of the release you run: every package of a release shares it. Keep them as peers, so the app installs one copy of each. The kernel finds contracts and extension points by the object itself, never by name, so a second copy of a package is a different contract, and your grant would reach no token endpoint (the `kernel` card).

Export the module the app imports at `./module`, as every module of the provider does: the app's `src/main.ts` imports it from there, as does the generator when it composes your package ([packages outside the release](outside-modules.md#export-the-module)).

<!-- generated:package-json -->
```json
{
	"name": "example-grant",
	"version": "1.0.0",
	"private": true,
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
		"@o3co/auth-provider-oauth": "<version>"
	}
}
```
<!-- end generated -->

## The grant

A grant is a contribution to the `grants` extension point (the `grants` card). This one gives a confidential client a token for itself, within what its allowance lets it ask, as the client credentials grant does (the `client-credentials` card). `readsAmbient` says the grant reads nothing the request carries beside its parameters; a grant that reads the session's cookie must say `cookie` and check the request's origin itself. The module's head declares `takes`, the handles its factories take from other modules: here `issuer`, the one contract its factory gets (the `kernel` card). Boot refuses a module that declares none; one that takes nothing declares `[]`.

<!-- generated:module -->
```ts
import { defineModule } from "@o3co/auth-provider-foundation/kernel";
import { clientAllowance } from "@o3co/auth-provider-oauth/client-allowance";
import { type Grant, grants } from "@o3co/auth-provider-oauth/grants";
import { issuer } from "@o3co/auth-provider-oauth/issuer";

/** The grant type a client names; a URI, as RFC 6749 asks of an extension grant. */
const grantType = "urn:example:params:oauth:grant-type:example";

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

export default defineModule({ name: "example-grant", takes: [issuer] }, (m) => [
	m.contribute(grants).by(async (c) => example((await c.get(issuer)).url)),
]);
```
<!-- end generated -->

If your grant calls another server, take `outbound`'s contract and send the request through it (the `outbound` card), so the operator's destination policy and limits apply. The guard's rule that holds the provider's own packages to that (G26, and the `network` declaration in a package manifest) reads only the provider's repository: in your package, nothing checks it but you.

## Add it to the app

Generate the app as the README's quick start shows, add your package to its dependencies, and add your module to the list the generated `src/main.ts` passes to `assemble`. (To have the generator compose it instead, declare it and install it as [packages outside the release](outside-modules.md) shows.)

<!-- generated:main -->
```ts
import exampleGrant from "example-grant/module";
// …
		return assemble({ modules: [exampleGrant, m0, m1, …], config });
```
<!-- end generated -->

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
- Values are plain JSON: strings, finite numbers, booleans, null, arrays and plain objects, at most 8 deep and 4 KiB in all. Anything else is refused. The `added-claims` module's card states every rule and limit.
- A refusal is a `TypeError`: the grant's mistake, answered as an error, not audited as a refused issuance.
- The token's issuance policies see the claims, and `verifyAccess` reads them back (`grant.claims`). The audit's `token.issued` names them, never their values.
- A refresh or an exchange issues no added claim. Do not use one for a restriction that must hold on such a token.
- The resource server cannot tell an added claim from one the provider wrote: composing your grant entrusts it with what its tokens say.
