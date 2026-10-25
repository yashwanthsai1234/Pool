// @legx/release-hash: the browser-safe half (manifest and release.json verification). The Node half is `./build.ts`.
export { cspHash, type FileHashes, injectSri, manifestHash, RELEASE_FILES, sha256Hex } from './manifest.ts';
export {
  compareVersions,
  RELEASE_CONTEXT,
  Release,
  ReleaseBody,
  ReleaseError,
  signRelease,
  verifyRelease,
} from './release.ts';
