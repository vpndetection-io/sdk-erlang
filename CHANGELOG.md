# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 3.3.2 are described by their release commits.

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
