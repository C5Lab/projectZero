import test from 'node:test';
import assert from 'node:assert/strict';
import { TransferMeter } from '../../docs/sd-transfer-stats.mjs';

const KiB = 1024;
const clock = () => {
  let time = 0;
  return { now: () => time, set: value => { time = value; } };
};

test('confirmed bytes yield rolling throughput, whole-operation average and ETA', () => {
  const time = clock();
  const meter = new TransferMeter(100 * KiB, { now: time.now });
  assert.equal(meter.snapshot().etaSeconds, null);
  time.set(1000);
  meter.progress(10 * KiB);
  assert.equal(meter.snapshot().currentBytesPerSecond, null);
  assert.equal(meter.snapshot().averageBytesPerSecond, 10 * KiB);
  assert.equal(meter.snapshot().etaSeconds, null);

  time.set(2000);
  meter.progress(20 * KiB);
  assert.equal(meter.snapshot().currentBytesPerSecond, 10 * KiB);
  assert.equal(meter.snapshot().etaSeconds, 8);
  time.set(6000);
  meter.progress(30 * KiB);
  const result = meter.snapshot();
  assert.equal(result.currentBytesPerSecond, 4 * KiB); // Five-second window starts at t=1 s.
  assert.equal(result.averageBytesPerSecond, 5 * KiB); // Whole operation starts at t=0.
  assert.equal(result.etaSeconds, 17.5);
});

test('ETA waits for one second and two samples, then disappears during a stall', () => {
  const time = clock();
  const meter = new TransferMeter(100 * KiB, { now: time.now });
  time.set(500);
  meter.progress(5 * KiB);
  assert.equal(meter.snapshot().etaSeconds, null);
  time.set(1000);
  meter.progress(10 * KiB);
  assert.equal(meter.snapshot().etaSeconds, 9);
  time.set(4001);
  const stalled = meter.snapshot();
  assert.equal(stalled.waiting, true);
  assert.equal(stalled.etaSeconds, null);
  assert.equal(stalled.currentBytesPerSecond, null);
  time.set(4100);
  meter.progress(11 * KiB);
  assert.equal(meter.snapshot().waiting, false);
});

test('sampler stays bounded and only verified completion ends finalizing', () => {
  const time = clock();
  const meter = new TransferMeter(1000, { now: time.now });
  for (let value = 1; value <= 1000; value++) {
    time.set(value * 10);
    meter.progress(value);
  }
  assert.ok(meter.samples.length <= 32);
  assert.equal(meter.snapshot().finalizing, true);
  assert.equal(meter.snapshot().finished, false);
  assert.equal(meter.snapshot().etaSeconds, null);
  time.set(11000);
  const finished = meter.finish();
  assert.equal(finished.finished, true);
  assert.equal(finished.finalizing, false);
  assert.equal(finished.averageBytesPerSecond, 1000 / 11);
});

test('zero-byte transfer never produces an invalid speed or ETA', () => {
  const time = clock();
  const meter = new TransferMeter(0, { now: time.now });
  time.set(500);
  const finished = meter.finish();
  assert.equal(finished.averageBytesPerSecond, null);
  assert.equal(finished.currentBytesPerSecond, null);
  assert.equal(finished.etaSeconds, null);
});

test('download header size can replace a stale directory listing size', () => {
  const time = clock();
  const meter = new TransferMeter(10, { now: time.now });
  time.set(1000);
  meter.progress(20, 20);
  const result = meter.snapshot();
  assert.equal(result.done, 20);
  assert.equal(result.total, 20);
  assert.equal(result.finalizing, true);
});

test('current link rate excludes upload CRC preparation while average includes it', () => {
  const time = clock();
  const meter = new TransferMeter(10 * KiB, { now: time.now });
  time.set(4000); // Local CRC preparation precedes the first ACK.
  meter.progress(1 * KiB);
  assert.equal(meter.snapshot().currentBytesPerSecond, null);
  assert.equal(meter.snapshot().etaSeconds, null);
  time.set(5000);
  meter.progress(2 * KiB);
  assert.equal(meter.snapshot().currentBytesPerSecond, 1 * KiB);
  assert.equal(meter.snapshot().averageBytesPerSecond, 0.4 * KiB);
  assert.equal(meter.snapshot().etaSeconds, 8);
});
