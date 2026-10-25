// The verifier opens no connections. The xrpl library imports `ws` for its network client, which is never used here;
// this stand-in keeps every socket, HTTP and TLS module out of verify.js (DESIGN 8.8 item 12).
export default class WebSocket {
  constructor() {
    throw new Error('legx-verify makes no network connections');
  }
}
