export const webauthnGrantType = "urn:o3co:oauth:grant-type:webauthn";

/** The amr a passkey login gives, whatever the authenticator's flags: possession of the key alone. */
export const passkeyAmr = ["hwk"] as const;
