// Stands in for `@xrplf/mpt-crypto` in the vault bundle (I-20). xrpl loads that 2.1 MB WASM only for Confidential Transfer
// transactions; the vault encodes and signs plain XRPL transactions and never builds one, so asking for it is an error.
// Source: https://github.com/XRPLF/xrpl.js/blob/main/packages/xrpl/src/confidential/loader.ts
throw new Error('@xrplf/mpt-crypto is not part of the vault bundle');
