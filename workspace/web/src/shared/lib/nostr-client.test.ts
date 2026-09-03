import { afterEach, describe, expect, it, vi } from "vitest";
import { queryEvents } from "./nostr-client";

type Listener = (event: { data?: string }) => void;

class FakeWebSocket {
  static instances: FakeWebSocket[] = [];

  private listeners = new Map<string, Listener[]>();

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this);
  }

  addEventListener(type: string, listener: Listener) {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  emit(type: string, event: { data?: string } = {}) {
    for (const listener of this.listeners.get(type) ?? []) listener(event);
  }

  send() {}

  close() {}
}

describe("queryEvents", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    FakeWebSocket.instances = [];
  });

  it("rejects a transport close before EOSE instead of caching partial events", async () => {
    vi.stubGlobal("WebSocket", FakeWebSocket);

    const query = queryEvents("ws://relay.test", { kinds: [30618] });
    const socket = FakeWebSocket.instances[0];
    expect(socket).toBeDefined();

    socket?.emit("close");

    await expect(query).rejects.toThrow("before EOSE");
  });
});
