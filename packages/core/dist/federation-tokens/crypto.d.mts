/**
 * Encrypts a string and returns `${version}.${iv}.${ct}.${tag}` where each
 * component is base64url-encoded. Version is included so that future algorithm
 * migrations can be detected on decrypt.
 */
export declare function encryptTokenField(plaintext: string, key: Buffer): string;
export declare function decryptTokenField(envelope: string, key: Buffer): string;
//# sourceMappingURL=crypto.d.mts.map