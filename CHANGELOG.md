# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 3.3.2 are described by their release commits.

## 3.10.2 - 2026-10-27

### Fixes

- Read a date-time in lowercase, as RFC 3339 allows ([`51adea1`](https://github.com/vpndetection-io/sdk-erlang/commit/51adea1f670553be6738a22b9722a0008fd11fea))

## 3.10.1 - 2026-10-26

### Fixes

- Re-pin the spec to 2026.10.25: Retry-After on myip's 429 ([`e850504`](https://github.com/vpndetection-io/sdk-erlang/commit/e850504db8271827a5c76ae6d2ff528817ffa782))

## 3.10.0 - 2026-10-24

### Features

- Add oauth_register, for RFC 7591 dynamic client registration ([`3de0e99`](https://github.com/vpndetection-io/sdk-erlang/commit/3de0e9925f3698e38fe476432f484a6a4d17dc4c))

## 3.9.1 - 2026-10-24

### Fixes

- Refuse an answer whose member has the wrong type, at any depth ([`c1d4354`](https://github.com/vpndetection-io/sdk-erlang/commit/c1d4354f21992699089ced4f732b5b6de3cf5670))

## 3.9.0 - 2026-10-20

### Features

- Add location and asn to lookup results, a bogon's included ([`0c57538`](https://github.com/vpndetection-io/sdk-erlang/commit/0c57538bc69ee02904e6b3e445b6dbd0b502740e))

## 3.8.1 - 2026-10-19

### Fixes

- Warn once when a core's result cache has stopped ([`a3ff6cd`](https://github.com/vpndetection-io/sdk-erlang/commit/a3ff6cda5c45f72d9a6913361f2d97c48ccf3534))

## 3.8.0 - 2026-10-19

### Features

- Re-pin the spec to 2026.10.19: num_ports and num_proxies in the pubproxy detail ([`6595868`](https://github.com/vpndetection-io/sdk-erlang/commit/6595868b1417e97afd3c363d7ea800b237155638))

## 3.7.0 - 2026-10-18

### Features

- Re-pin the spec to 2026.10.18: is_pubproxy and the pubproxy detail ([`43c4c0a`](https://github.com/vpndetection-io/sdk-erlang/commit/43c4c0a7cec9ac5bf2bfa7559f5bdf38a82ba313))
- Add a selector for the PROXY protocol's source address ([`d8f2498`](https://github.com/vpndetection-io/sdk-erlang/commit/d8f2498b00398a59f00ebd4d0bb19a7f1a1ec276))

## 3.6.0 - 2026-10-17

### Features

- Re-pin the spec to 2026.10.16: dynamic client registration ([`2669838`](https://github.com/vpndetection-io/sdk-erlang/commit/2669838eb06790b0ad00a1afc7c685e87814869b))

### Fixes

- Take a nil key and an address tuple, and end the cache with its owner ([`8425619`](https://github.com/vpndetection-io/sdk-erlang/commit/84256199ef1810333a19144de8511ee600ec6d98))
- Middleware: warn on a nil key, and name only the ip_selector for a proxy ([`09121a4`](https://github.com/vpndetection-io/sdk-erlang/commit/09121a4ea124f65e3067026efd033a39c791daeb))

## 3.5.3 - 2026-10-16

### Fixes

- Re-pin the spec to 2026.10.15: descriptions in US spelling ([`6d88e6e`](https://github.com/vpndetection-io/sdk-erlang/commit/6d88e6ec3af069038057dd9294d5690ca46d99f6))

## 3.5.2 - 2026-10-14

### Fixes

- Read Retry-After as digits or an RFC 9110 date in GMT, never crashing ([`8087116`](https://github.com/vpndetection-io/sdk-erlang/commit/80871167cbb8584ab5285933b265c8c5dcd7c31b))
- Trim the key and refuse a control character in it; retry an unreadable 2xx ([`183ffdd`](https://github.com/vpndetection-io/sdk-erlang/commit/183ffdd46c7315614675e3d9fb1d4443b2138bd4))

## 3.5.1 - 2026-10-10

### Fixes

- Re-pin the spec to 2026.10.09: rotating a key needs apikeys.reveal ([`fd0af50`](https://github.com/vpndetection-io/sdk-erlang/commit/fd0af502489a402a2ed502a9be4021a8a52b04f6))

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
