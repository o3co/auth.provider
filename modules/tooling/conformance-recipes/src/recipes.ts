/** The generate command of each recipe, after the target directory: one constant shown and run. */
export const commands = {
	/** Password login, TOTP as the only second factor, users from an HTTP ledger, Redis. */
	"mfa-page": [
		"--pattern",
		"simple-web",
		"--axis",
		"@mod/store=@mod/redis",
		"--axis",
		"@mod/users=@mod/users-http",
		"--second-factor",
		"@mod/mfa,@mod/mfa-flows,@mod/mfa-totp",
	],
	/** The default web login: a password, users in the configuration, the store in memory. */
	"first-login": ["--pattern", "simple-web"],
} as const satisfies Record<string, readonly string[]>;

/** Scripts a recipe's reader runs with `node -e`, each one constant shown and run. */
export const scripts = {
	/** Prints a new Ed25519 signing key as PKCS8 PEM. */
	"signing-key":
		'console.log(require("node:crypto").generateKeyPairSync("ed25519").privateKey.export({format:"pem",type:"pkcs8"}).trim())',
	/** Reads a password on standard input and prints its scrypt hash in the form secret-hash reads. */
	"password-hash":
		'const c=require("node:crypto"),s=c.randomBytes(16),p=require("node:fs").readFileSync(0,"utf8").replace(/\\r?\\n$/,""),k=c.scryptSync(p,s,32,{N:2**15,r:8,p:1,maxmem:2**26}),b=(x)=>x.toString("base64").replace(/=+$/,"");console.log(`$scrypt$ln=15,r=8,p=1$${b(s)}$${b(k)}`)',
} as const;

/** A script as a reader types it. */
export const shownScript = (script: string) => `node -e '${script}'`;

/** The command as a reader types it, from the published entrance. */
export const shownCommand = (argv: readonly string[]) =>
	["npx @o3co/create-auth-provider@next my-provider", ...argv].join(" ");
