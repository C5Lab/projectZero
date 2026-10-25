const WINDOW_MS = 5000;
const SAMPLE_GAP_MS = 250;
const MAX_SAMPLES = 32;
const STALL_MS = 3000;

// Rates use acknowledged payload bytes, not serial framing or unverified data.
export class TransferMeter {
  constructor(total, { now = () => performance.now() } = {}) {
    if (!Number.isSafeInteger(total) || total < 0) throw new Error('Invalid transfer size.');
    this.now = now;
    this.total = total;
    this.startedAt = now();
    this.done = 0;
    this.lastProgressAt = null;
    this.finishedAt = null;
    this.samples = [];
  }

  progress(done, total = this.total) {
    if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(done)
        || done < this.done || done > total) {
      throw new Error('Invalid transfer progress.');
    }
    const at = this.now();
    if (done > this.done) this.lastProgressAt = at;
    this.total = total;
    this.done = done;
    const last = this.samples.at(-1);
    if (!last || at - last.at >= SAMPLE_GAP_MS || done === this.total) {
      if (last?.at === at) last.done = done;
      else this.samples.push({ at, done });
    }
    while (this.samples.length > 1 && this.samples[0].at < at - WINDOW_MS) this.samples.shift();
    while (this.samples.length > MAX_SAMPLES) this.samples.shift();
  }

  snapshot() {
    const at = this.finishedAt ?? this.now();
    const elapsedMs = Math.max(0, at - this.startedAt);
    const first = this.samples[0];
    const last = this.samples.at(-1);
    const sampledMs = first && last ? last.at - first.at : 0;
    const sampledBytes = first && last ? last.done - first.done : 0;
    const waiting = this.finishedAt === null && this.lastProgressAt !== null
      && at - this.lastProgressAt > STALL_MS;
    const currentBytesPerSecond = !waiting && sampledMs > 0 && sampledBytes > 0
      ? sampledBytes * 1000 / sampledMs : null;
    const averageBytesPerSecond = elapsedMs > 0 && this.done > 0
      ? this.done * 1000 / elapsedMs : null;
    const finalizing = this.finishedAt === null && this.total > 0 && this.done === this.total;
    const etaSeconds = !waiting && !finalizing && this.finishedAt === null
      && elapsedMs >= 1000 && this.samples.length >= 2 && currentBytesPerSecond > 0
      ? (this.total - this.done) / currentBytesPerSecond : null;
    return {
      done: this.done,
      total: this.total,
      elapsedMs,
      currentBytesPerSecond,
      averageBytesPerSecond,
      etaSeconds,
      waiting,
      finalizing,
      finished: this.finishedAt !== null,
    };
  }

  finish() {
    if (this.finishedAt === null) this.finishedAt = this.now();
    return this.snapshot();
  }
}
