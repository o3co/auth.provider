/** The bytes a renewal nonce is minted from: 128 bits. */
export declare const RENEWAL_NONCE_BYTES = 16;
/** A fresh renewal nonce: {@link RENEWAL_NONCE_BYTES} from the CSPRNG, base64url. */
export declare const newRenewalNonce: () => string;
/** Whether `value` is a renewal nonce as {@link newRenewalNonce} spells one. */
export declare const isRenewalNonce: (value: unknown) => value is string;
//# sourceMappingURL=renewalNonce.d.mts.map