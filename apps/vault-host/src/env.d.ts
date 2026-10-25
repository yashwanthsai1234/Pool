// Constants the build bakes into the bundle (vite.config.ts `define`). They are part of the hashed bytes.
declare const __RELEASE_URL__: string; // where release.json is published: neither the coordinator nor the app origin
declare const __RELEASE_KEYS__: { ed25519: string; mlDsa65: string }; // release public keys, hex
declare const __VAULT_VERSION__: string;
