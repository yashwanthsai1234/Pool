// A script the probe page's policy allows (its hash is added to script-src). It tries what the vault page must not
// allow and tells the parent which attempts worked. The mode comes from the URL fragment.
const mode = location.hash.slice(1);
const say = (m) => parent.postMessage(m, '*');
if (mode === 'bad-ready') {
  say({ legxVaultHost: 1, type: 'ready', version: '1.0.0', manifestHash: 'not-a-hash', extra: 1 });
  say({ legxVaultHost: 1, type: 'refused', code: 'SOMETHING_ELSE' });
  say('ready');
} else {
  try {
    // biome-ignore lint/security/noGlobalEval: the policy must block exactly this call
    say(`eval-ran:${eval('1+1')}`);
  } catch {
    say('eval-blocked');
  }
  try {
    document.body.innerHTML = '<b>x</b>';
    say('innerhtml-ran');
  } catch {
    say('innerhtml-blocked');
  }
  try {
    const a = document.createElement('a');
    a.href = 'javascript:parent.postMessage("javascript-url-ran","*")';
    document.body.append(a);
    a.click();
  } catch {
    say('javascript-url-blocked');
  }
  setTimeout(() => say('probe-done'), 300);
}
