# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 3.3.2 are described by their release commits.

## 3.5.0 - 2026-10-05

### Features

- Add the authorization code sign-in, with PKCE ([`23f8da8`](https://github.com/vpndetection-io/sdk-erlang/commit/23f8da89d197f8613b34b12cea9ea7c6332380e1))

### Fixes

- Hand a 503 to the client's retries at once on OTP 28.4 and later ([`e184ac3`](https://github.com/vpndetection-io/sdk-erlang/commit/e184ac393f5fd6d4f91adb02292646bce6d71842))

## 3.4.3 - 2026-10-04

### Fixes

- Re-pin the spec to 2026.10.03: metadata needs no license ([`839d50b`](https://github.com/vpndetection-io/sdk-erlang/commit/839d50bba4ad923b1faca548ae05a40b63caf114))

## 3.4.2 - 2026-10-01

### Fixes

- Share one request per address among concurrent lookups and batches ([`6356d42`](https://github.com/vpndetection-io/sdk-erlang/commit/6356d42c1fd243cbb33eb1a65bab4986601d8fca))
- Leave the caller's own monitor messages alone during a batch ([`e27ec3b`](https://github.com/vpndetection-io/sdk-erlang/commit/e27ec3b6a99618bf02902d706aeaea13c1f8cdea))

## 3.4.1 - 2026-09-29

### Fixes

- Judge an IPv4-mapped address as the IPv4 address it carries ([`0c429dd`](https://github.com/vpndetection-io/sdk-erlang/commit/0c429dd2b0927b07ec3f5da1d8c1714d98717fb3))
- Recognize 26 more reserved ranges as bogons, as the API does ([`4c20b69`](https://github.com/vpndetection-io/sdk-erlang/commit/4c20b694950c669dab89797d1cd7b3c8857b1cda))

## 3.4.0 - 2026-09-27

### Features

- Re-pin the spec to 2026.09.26, adding client_id_metadata_document_supported ([`0027759`](https://github.com/vpndetection-io/sdk-erlang/commit/002775908d8c932863142e1c60dc923d5d737a24))

## 3.3.2 - 2026-09-23

### Fixes

- Drop every trailing slash, refuse impossible timeouts, bound waits ([`0e19828`](https://github.com/vpndetection-io/sdk-erlang/commit/0e1982886398205c8b527c8a97bbb2d73a80514c))
