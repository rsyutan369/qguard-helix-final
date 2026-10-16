// happy-dom has no WebSocket, and the Supabase realtime client refuses to be
// constructed without one. No unit test opens a socket, so a constructor that
// fails loudly if one ever tries is all the environment needs.
if (typeof globalThis.WebSocket === "undefined") {
  class UnavailableWebSocket {
    constructor() {
      throw new Error("WebSocket is not available in unit tests");
    }
  }
  globalThis.WebSocket = UnavailableWebSocket as unknown as typeof WebSocket;
}
