export const webauthnGrantType = "urn:o3co:oauth:grant-type:webauthn";

/**
 * The amr a passkey login gives, whatever the authenticator's flags: possession of the key alone,
 * how the key is kept unsaid (OpenID Connect EAP ACR Values), as no attestation is asked.
 */
export const passkeyAmr = ["pop"] as const;
