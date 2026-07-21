# Upstream DeepSec baseline

This Grok Build plugin is a **zero-Node refactor/port** of
[vercel-labs/deepsec](https://github.com/vercel-labs/deepsec).

| Field | Value |
|-------|--------|
| **Upstream package version** | **2.2.4** (`packages/deepsec/package.json`) |
| **Upstream git commit** | `97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04` |
| **Commit date (UTC)** | 2026-07-19 |
| **Commit summary** | Fix unbounded memory growth during sandbox downloads (#115) |
| **Tree URL** | https://github.com/vercel-labs/deepsec/tree/97ebd04b455a492dfd5b9ad86f2dd9cf8b05fa04 |
| **Port date** | 2026-07-21 |
| **This plugin version** | 1.0.0 |

## What “refactored after” means

Behavior, pipeline stages, FileRecord/RunMeta shapes, matcher set (extracted
from the scanner package at this commit), and command surface were taken from
upstream **deepsec 2.2.4** at the commit above. The implementation is **not**
a line-for-line TypeScript port: Node/pnpm, Vercel sandbox/OIDC, and external
agent SDKs are replaced by pure Python + Grok skills/sub-agents.

## Machine-readable pin

See `SOURCE_REV` in this directory (same commit SHA and version).
