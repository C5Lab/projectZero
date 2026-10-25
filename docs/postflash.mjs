const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const C5_WDT_WRITES = [
  [0x600b1c18, 0x50d83aa1],
  [0x600b1c04, 2000],
  [0x600b1c00, 0xd0000102],
  [0x600b1c18, 0],
];

export async function resetWithWatchdog(loader, { sleep = wait } = {}) {
  let uncertainStep = 0;
  for (let index = 0; index < C5_WDT_WRITES.length; index++) {
    try {
      await loader.writeReg(...C5_WDT_WRITES[index]);
    } catch (error) {
      // The third write arms the WDT. Its ACK or the final lock ACK may be
      // lost when the chip resets, so the boot probe decides the outcome.
      if (index < 2) throw error;
      uncertainStep = index + 1;
      break;
    }
  }
  await sleep(500);
  return uncertainStep
    ? { acknowledgement: "uncertain", failedStep: uncertainStep }
    : { acknowledgement: "complete" };
}

export async function verifyJanosBoot(runCommand, {
  expectedVersion,
  attempts = 10,
  sleep = wait,
  pingTimeoutMs = 1500,
  versionTimeoutMs = 1500,
} = {}) {
  // Branch manifests may use "latest" as a source label, not a JanOS version.
  // Compare only a concrete version; a leading "v" is common in release tags.
  const explicitVersion = /^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)$/.exec(expectedVersion || '')?.[1];
  for (let index = 0; index < attempts; index++) {
    try {
      const ping = await runCommand("ping", /(?:^|\s)pong(?:\s|$)/i, pingTimeoutMs);
      if (ping.matched) {
        const response = await runCommand("version", /JanOS version:\s*\S+/i, versionTimeoutMs);
        const version = /JanOS version:\s*([^\s]+)/i.exec(response.received || "")?.[1];
        if (response.matched && version) {
          if (explicitVersion && version !== explicitVersion) {
            return { ok: false, reason: "version_mismatch", version };
          }
          return { ok: true, version };
        }
      }
    } catch {
      // The COM port can disappear briefly during the full SoC reset.
    }
    if (index + 1 < attempts) await sleep(1000);
  }
  return { ok: false, reason: "boot_unconfirmed" };
}
