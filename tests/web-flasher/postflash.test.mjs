import test from "node:test";
import assert from "node:assert/strict";
import { resetWithWatchdog, verifyJanosBoot } from "../../docs/postflash.mjs";

test("watchdog reset writes only the ESP32-C5 WDT registers in order", async () => {
  const calls = [];
  const loader = { writeReg: async (...args) => calls.push(args) };
  const result = await resetWithWatchdog(loader, { sleep: async (ms) => calls.push(["wait", ms]) });
  assert.deepEqual(calls, [
    [0x600b1c18, 0x50d83aa1],
    [0x600b1c04, 2000],
    [0x600b1c00, 0xd0000102],
    [0x600b1c18, 0],
    ["wait", 500],
  ]);
  assert.deepEqual(result, { acknowledgement: "complete" });
});

test("lost ACK after arming WDT still proceeds to boot verification", async () => {
  let index = 0;
  const loader = { writeReg: async () => { if (++index === 4) throw new Error("serial disconnected"); } };
  const result = await resetWithWatchdog(loader, { sleep: async () => {} });
  assert.equal(index, 4);
  assert.equal(result.acknowledgement, "uncertain");
});

test("boot verifier retries and confirms JanOS version after pong", async () => {
  const commands = [];
  let pings = 0;
  const runCommand = async (command) => {
    commands.push(command);
    if (command === "ping") return { matched: ++pings >= 2, received: pings >= 2 ? "pong\r\n" : "" };
    return { matched: true, received: "JanOS version: 1.7.5\r\n" };
  };
  const result = await verifyJanosBoot(runCommand, { expectedVersion: "1.7.5", attempts: 3, sleep: async () => {} });
  assert.deepEqual(commands, ["ping", "ping", "version"]);
  assert.deepEqual(result, { ok: true, version: "1.7.5" });
});

test("boot verifier reports a booted but unexpected JanOS version", async () => {
  const runCommand = async (command) => command === "ping"
    ? { matched: true, received: "pong\n" }
    : { matched: true, received: "JanOS version: 1.7.4\n" };
  const result = await verifyJanosBoot(runCommand, { expectedVersion: "1.7.5", sleep: async () => {} });
  assert.deepEqual(result, { ok: false, reason: "version_mismatch", version: "1.7.4" });
});

test("latest manifest accepts the concrete JanOS version reported after pong", async () => {
  const commands = [];
  const runCommand = async (command) => {
    commands.push(command);
    return command === "ping"
      ? { matched: true, received: "pong\r\n" }
      : { matched: true, received: "JanOS version: 1.7.5\r\n" };
  };
  const result = await verifyJanosBoot(runCommand, { expectedVersion: "latest", sleep: async () => {} });
  assert.deepEqual(commands, ["ping", "version"]);
  assert.deepEqual(result, { ok: true, version: "1.7.5" });
});

test("boot verifier reports unconfirmed start after bounded attempts", async () => {
  let calls = 0;
  const result = await verifyJanosBoot(async () => { calls++; return { matched: false, received: "" }; },
    { expectedVersion: "1.7.5", attempts: 2, sleep: async () => {} });
  assert.equal(calls, 2);
  assert.deepEqual(result, { ok: false, reason: "boot_unconfirmed" });
});
