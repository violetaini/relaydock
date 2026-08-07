# Arcway Telegram Bot integration

This directory contains an unofficial Arcway integration derived from the
Telegram Bot and Mini App implementation in Miaomiaowu X, upstream revision
`31b5b65`. The corresponding source-available license and copyright notice are
preserved in [`LICENSE`](LICENSE).

The integration changes the upstream implementation in these ways:

- embeds the Bot and Mini App in the Arcway Go process and reuses Arcway's
  authenticated admin API and SQLite storage;
- adds Arcway system-settings controls, announcement persistence, and an
  atomic, disabled-by-default runtime lifecycle;
- replaces upstream names, logos, artwork, and public URLs with Arcway
  branding and the Arcway default asset;
- hardens Telegram `initData` validation, preview authentication, request
  limits, and delivery retry behavior for the Arcway deployment.

The files in this directory remain subject to the terms of `LICENSE`. The
surrounding Arcway code retains its own repository license where it is not a
derivative of the upstream implementation.
