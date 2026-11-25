# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 3.3.2 are described by their release commits.

## 3.20.1 - 2026-11-25

### Fixes

- README: one paid plan, Data; the entitlement example names it ([`456620b`](https://github.com/vpndetection-io/sdk-erlang/commit/456620b334442ffbbd074d18148b06786f157ce1))
- Spec 2026.11.25: descriptions name a paid plan, the entitlement example the Data plan ([`ae6c91b`](https://github.com/vpndetection-io/sdk-erlang/commit/ae6c91b575bc7e7caa18b740890879be15e3a36d))
- Type docs name a paid plan, now that Data is the only one ([`85e48ef`](https://github.com/vpndetection-io/sdk-erlang/commit/85e48ef22b1b0dd375166124138f92c8ee05e82a))

## 3.20.0 - 2026-11-24

### Fixes

- Middleware: a condition on a list member matches any element ([`1f2f05c`](https://github.com/vpndetection-io/sdk-erlang/commit/1f2f05c56966c4c6749346920efd2a1c04b3b2cb))

## 3.19.1 - 2026-11-24

### Fixes

- Refuse a cache option no lookup could use when the client is built ([`8c2d86c`](https://github.com/vpndetection-io/sdk-erlang/commit/8c2d86c3c8c7c7190f8922a647af72ebaa452915))
- Answer a database_downloads limit that is no count with bad_request ([`efd5c82`](https://github.com/vpndetection-io/sdk-erlang/commit/efd5c82d894a4461f9bc26d7b5f28adee22c5360))
- Middleware: refuse an option no request could use when it is built ([`6cbf9d2`](https://github.com/vpndetection-io/sdk-erlang/commit/6cbf9d21b427e2e120b7aa927eeb17830617d6cc))

## 3.19.0 - 2026-11-24

### Features

- Send the user agent of the request you are deciding on with a lookup ([`d9be7ce`](https://github.com/vpndetection-io/sdk-erlang/commit/d9be7ce4f5ea0c289346ddb791b72e5be6834f59))
- Middleware: allow_bots lets a crawler its operator vouches for through ([`06d316f`](https://github.com/vpndetection-io/sdk-erlang/commit/06d316f3891175930506200d45b913375911c1a4))

### Fixes

- Read the bot, service and BitTorrent details' first and last seen days as dates ([`3412075`](https://github.com/vpndetection-io/sdk-erlang/commit/341207562f557799aaeb53d4f9ffdaeb27104f8b))

## 3.18.0 - 2026-11-22

### Features

- Answer is_bot and the bot detail on every lookup ([`bc88383`](https://github.com/vpndetection-io/sdk-erlang/commit/bc88383af7428a9fb688256aa8295f91e4b16401))

### Fixes

- Require the AS's country and RPKI status, as the API always sends them ([`10a434a`](https://github.com/vpndetection-io/sdk-erlang/commit/10a434a4d6d63844c9205bc5d2231edbb3512a65))

## 3.17.0 - 2026-11-20

### Features

- Read the network, service, company and abuse members of an answer ([`59a453b`](https://github.com/vpndetection-io/sdk-erlang/commit/59a453b2acb7f543845091f09f23a62de262b096))

### Fixes

- Cache a spent trial's or a reached cap's answer for a minute at most ([`588ee96`](https://github.com/vpndetection-io/sdk-erlang/commit/588ee966c7eebbb782c48bce40e63e81848e354f))

## 3.16.1 - 2026-11-19

### Fixes

- Re-pin the spec to 2026.11.18: a key over plain HTTP is refused ([`c68da90`](https://github.com/vpndetection-io/sdk-erlang/commit/c68da90d9b76ce85704c66aec5d3517010c82ffe))

## 3.16.0 - 2026-11-18

### Features

- Read cap_reached past a paid plan's overage cap, and re-pin the spec ([`5b4c16d`](https://github.com/vpndetection-io/sdk-erlang/commit/5b4c16dcc1a8ec171a0057508365f88f77aa8214))

## 3.15.0 - 2026-11-16

### Features

- Read the plan's name, required beside its key ([`620ac81`](https://github.com/vpndetection-io/sdk-erlang/commit/620ac8195b15d10200d2f0c10c2789c924265180))

## 3.14.0 - 2026-11-15

### Features

- Re-pin the spec to 2026.11.14: is_bogon on every answer, and provider_name beside each provider ([`4647df3`](https://github.com/vpndetection-io/sdk-erlang/commit/4647df363ff9cc628bdffcebdbbd82759cb0b070))

### Fixes

- README: a bogon answers is_bogon true and every other flag false ([`333a655`](https://github.com/vpndetection-io/sdk-erlang/commit/333a655210cf77d4552e79933701217f969d1a88))
- Release: fail when hex.pm only stages the publish for approval ([`6f432d3`](https://github.com/vpndetection-io/sdk-erlang/commit/6f432d37c5f8b56e57203a0d8a1f234bb803e471))
- Say that a batch request of one address is answered as its lookup ([`85151b5`](https://github.com/vpndetection-io/sdk-erlang/commit/85151b510bb904b978599607f60370767a53508e))
- Re-pin the spec to 2026.11.12: plainer words on the 401 and the batch rate limit ([`e58a38e`](https://github.com/vpndetection-io/sdk-erlang/commit/e58a38e6cb0790c6629be570bde3f498ae646209))

## 3.13.1 - 2026-11-11

### Fixes

- Say the free plan's daily trial and Unlimited, the free plan, and re-pin the spec ([`325c79c`](https://github.com/vpndetection-io/sdk-erlang/commit/325c79ca413e4caf6a5a2d3ea014129e7a2c135a))

## 3.13.0 - 2026-11-11

### Features

- Add trial_expired for a trial key's answers, and re-pin the spec ([`06a2009`](https://github.com/vpndetection-io/sdk-erlang/commit/06a20095175b3e432a8e0a191dc86527dc67f5c6))

## 3.12.2 - 2026-11-11

### Fixes

- Name the Unlimited tier and its terms, and re-pin the spec ([`114859e`](https://github.com/vpndetection-io/sdk-erlang/commit/114859eabc9182fcb04d40d3d715c4f8a8c64469))

## 3.12.1 - 2026-11-11

### Fixes

- Re-pin the spec's 2026.11.11 rebuild: plainer words on lookups without a key ([`5da03ed`](https://github.com/vpndetection-io/sdk-erlang/commit/5da03ed82a3121691c0d4707bf73fba023a3dc48))

## 3.12.0 - 2026-11-11

### Features

- Re-pin the spec to 2026.11.11: a lookup without a key answers more ([`cb81020`](https://github.com/vpndetection-io/sdk-erlang/commit/cb8102004a66e74304ea9c54971ef8ea5e9c51b9))

## 3.11.1 - 2026-11-08

### Fixes

- Refuse a client concurrency that is not an integer of 1 or more in new/1 ([`8dc0567`](https://github.com/vpndetection-io/sdk-erlang/commit/8dc0567a1a099c08528c4227116017c71a695a3e))

## 3.11.0 - 2026-11-07

### Features

- Download the build a database.updated webhook names ([`5884696`](https://github.com/vpndetection-io/sdk-erlang/commit/5884696147666ff5e3d151137eafdcd4f24ea8d1))

### Fixes

- Re-pin the spec to 2026.11.05: the download's build parameter ([`f086519`](https://github.com/vpndetection-io/sdk-erlang/commit/f086519d9f32564e8568d45fcc47ff4c0bfccb79))
- Re-pin the spec to 2026.11.03: a proxy flag keeps its last values ([`731b88f`](https://github.com/vpndetection-io/sdk-erlang/commit/731b88f64ad8acfa82fb5cb29dbc81ce1b126b31))
- Re-pin the spec to 2026.11.02: ID and IDs in its descriptions ([`1bf0553`](https://github.com/vpndetection-io/sdk-erlang/commit/1bf0553332b573c09ce6171992be3a4031277568))
- Re-pin the spec to 2026.11.02: two spent-allowance messages ([`183c943`](https://github.com/vpndetection-io/sdk-erlang/commit/183c943bd6220017baca8e7132efdee36d5958d0))

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
