---
id: 1
title: Legacy output compatibility requires collection replay
status: open
type: internal
skill: [test-driven-development, verification-before-completion]
proposes_skill: []
siblings_checked: "No family registry; evaluated test-driven-development and verification-before-completion together, applies to both."
area: compatibility regression coverage
date: 2026-10-05
session_context: Passive Wi-Fi reporting extension changed legacy client collection
---
Exact command-output fixtures passed while collection decisions changed. User hardware feedback exposed the gap. A differential replay of frozen original and production callbacks failed for selected historical APs, timestamps, and hopping; restoring the legacy pipeline made it pass. For additive reporting, require both byte-output comparisons and state-transition replay before claiming compatibility. Hardware success still requires device evidence.

Hardware follow-up: actual C5 metadata sig_len=604/dump_len=608 contradicted fixture assumptions and produced bad_length=rx. Added exact-metadata replay through the production callback and results command. Differential collection tests had correctly preserved legacy decisions but did not validate adapter metadata across firmware targets. Keep software verification distinct from device validation and seed adapter fixtures with observed target metadata.

Hidden-SSID validation follow-up: visible client records do not prove receipt of a name-bearing association/reassociation/probe-response. Added on-demand request counters and last-request metadata; tests verify production hidden-beacon?association/reassociation discovery and persistence. Distinguish absent radio evidence from parser rejection before proposing a parser change.
