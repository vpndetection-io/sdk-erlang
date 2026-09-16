# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="24"/>](https://vpndetection.io/) VPNDetection Erlang Client Library

[![hex.pm](https://img.shields.io/hexpm/v/vpndetection.svg)](https://hex.pm/packages/vpndetection)
[![license](https://img.shields.io/hexpm/l/vpndetection.svg)](LICENSE)

The official Erlang client library for the [VPNDetection](https://vpndetection.io) API.

The library helps you query VPNDetection's APIs for anonymity detection including VPNs, residential proxies, Tor nodes, hosting servers, CDNs, relays and more.

## Getting Started

```erlang
%% rebar.config
{deps, [vpndetection]}.
```

Requires Erlang/OTP 27 or newer. There are no runtime dependencies: everything the client needs is in OTP. From Elixir, add `{:vpndetection, "~> 3.2"}` to your `mix.exs` deps and call it as `:vpndetection`.

## Usage

**No API key needed to start.** The free tier answers `ip` and `is_vpn`, and allows 1000 requests per day per source address.

```erlang
Client = vpndetection:new(),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result).   % true
```

Every call answers `{ok, Term}` or `{error, Error}`. A client holds a cache, which is a process, so build one somewhere long lived and call `vpndetection:close(Client)` when you are finished with it.

### With an API key

An API key raises your quota, and raises your features on a paid plan. Create one in the [console](https://app.vpndetection.io), then pass it in:

```erlang
Client = vpndetection:new(#{api_key => <<"your-api-key">>}),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result).                        % true
maps:get(provider, maps:get(vpn, Result)).       % <<"mullvad">>
maps:get(is_hosting, Result).                    % true
maps:get(provider, maps:get(hosting, Result)).   % <<"M247">>
```

A detail map that is present but empty (`#{}`) means the flag above it is false. A populated one always carries every one of its keys.

### Your own address

```erlang
{ok, Result} = vpndetection:my_ip(Client),
maps:get(ip, Result).   % the address we saw this call come from
```

Same answer `lookup` would give for that address, and the same cost against your allowance. It is deliberately not cached: which address you are is the whole question, and a machine that moves between networks would otherwise be told where it used to be.

### Your plan and usage

```erlang
{ok, Entitlement} = vpndetection:my_entitlement(Client),
Plan = maps:get(<<"plan">>, Entitlement),
Usage = maps:get(<<"usage">>, Entitlement),
maps:get(<<"key">>, Plan).         % <<"max">>
maps:get(<<"requests">>, Usage).   % 580
maps:get(<<"window_end">>, Usage). % when the allowance resets
```

Usage counts against the anniversary of your subscription, not the calendar month and not the billing period, and it is the same number a lookup is gated on. `hard_limit` is `null` on an uncapped plan, which is not the same as zero.

Note the key types differ: a lookup answers a map with ATOM keys, while the entitlement answers the decoded JSON with BINARY keys. `my_ip/2` and `my_entitlement/2` take a per-call options map.

### Batch lookup

Look up as many addresses as you like at once. Bogons and cached answers are handled locally, and everything else goes to the batch endpoint in chunks of up to 1000 addresses, in parallel:

```erlang
Results = vpndetection:lookup_batch(Client, [<<"45.83.91.1">>, <<"8.8.8.8">>, <<"1.1.1.1">>]),

maps:foreach(fun
    (Ip, {ok, Result}) -> io:format("~s: ~p~n", [Ip, maps:get(is_vpn, Result)]);
    (Ip, {error, Error}) -> io:format("~s: ~s~n", [Ip, maps:get(message, Error)])
end, Results).
```

Results are keyed by address, so duplicates in your list collapse into a single entry and one address failing never loses the rest: it carries its error as its value, with the status the API would have given that address on its own. Erlang maps carry no order, so iterate your own list when order matters.

How many chunks are in flight at once, how many times a failed chunk is retried, and how long each chunk's request may take are configurable per call:

```erlang
Results = vpndetection:lookup_batch(Client, ManyIps, #{concurrency => 4, retries => 4, timeout_ms => 5000}).
```

### Caching

Answers are cached by default, so repeat lookups of the same address are free:

```erlang
Client = vpndetection:new(),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result).    % true, API request

{ok, Result2} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result2).   % true, no API request, result was cached
```

You can change the default cache variables (max size, TTL, etc) on initialization, or even disable it:

```erlang
Client = vpndetection:new(#{cache => #{max => 50000, ttl_ms => 6 * 60 * 60 * 1000}}),
ClientNoCache = vpndetection:new(#{cache => false}).
```

The cache belongs to one client and is never shared, because two clients holding different keys are on different plans and so entitled to different fields. It is owned by a process linked to whoever called `new/1`, so a client built inside a short-lived process loses its cache when that process ends. `vpndetection:close(Client)` releases it; a client built with `cache => false` starts no process at all and needs no closing.

### Private and reserved addresses

Private, loopback, link-local, documentation and multicast addresses (and their IPv6 equivalents, including the 6to4 and Teredo ranges) can never be VPN or proxy infrastructure. The library answers them locally, so they cost no request and no quota:

```erlang
{ok, Result} = vpndetection:lookup(Client, <<"192.168.1.1">>),
maps:get(is_bogon, Result).   % true, this answer was computed rather than served
maps:get(is_vpn, Result).     % false
```

A locally computed answer is deliberately the widest shape the API serves, so every flag is present and false and every detail map is present and empty. Do not read your plan's features off one.

The check is available on the client, which is handy when your inputs are addresses anyway:

```erlang
vpndetection:is_bogon(Client, <<"10.0.0.1">>).   % true
vpndetection:is_bogon(Client, <<"8.8.8.8">>).    % false
```

It is also callable on its own, if you want it without a client:

```erlang
vpndetection:is_bogon(<<"10.0.0.1">>).   % true
```

### Errors

A failure answers `{error, Error}`, where `Error` is a map carrying a `kind` and a `retryable` flag:

```erlang
case vpndetection:lookup(Client, <<"1.1.1.1">>) of
    {ok, Result} ->
        maps:get(is_vpn, Result);
    {error, #{kind := unauthorized}} ->
        check_your_api_key();
    {error, Error} ->
        io:format("~p: ~s~n", [maps:get(kind, Error), maps:get(message, Error)])
end.
```

`kind` is one of `bad_request`, `unauthorized`, `forbidden`, `rate_limited`, `quota_exceeded`, `server_error` or `network`. `status` carries the HTTP status where there was one.

Note that `rate_limited` and `quota_exceeded` both arrive as HTTP 429 and are not the same thing. A rate limit is when the API faces extreme traffic bursts and so retrying later works; but a spent quota needs your allowance raised or the window to roll over. The library retries rate limits for you, but not if your quota is exceeded.

### Timeouts and retries

```erlang
Client = vpndetection:new(#{retries => 4, timeout_ms => 30000}),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>, #{retries => 0, timeout_ms => 2000}).
```

`timeout_ms` bounds each attempt, body included, so a call that is retried can take longer in total. The client's values are defaults: `lookup/3`, `lookup_batch/3`, `my_ip/2` and `my_entitlement/2` each take `retries` and `timeout_ms` for that call alone, and every `oauth_*` function takes `timeout_ms`. During a download it bounds the wait between chunks instead, because a whole transfer can take minutes.

### Database downloads

If your key carries the `db.download` scope, the licensed databases are available too:

```erlang
{ok, Datasets} = vpndetection:database_list(Client),
{ok, Url} = vpndetection:database_download_url(Client, <<"vpn_ip_extended_v1">>, mmdb),
{ok, Checksums} = vpndetection:database_checksums(Client, <<"vpn_ip_extended_v1">>, mmdb).
```

`database_download_url/3` returns a time-limited link rather than the bytes, so you choose how to transfer a file that can run to gigabytes. `vpndetection:database_formats()` lists the formats these take, for checking one that came from a flag or a config file, and `standings()` and `license_types()` list what a family's `standing` and `license_type` can be.

### Sign in with OAuth (device flow)

A program running on a person's own machine can let them sign in with their browser and pick one of their API keys, instead of asking them to paste one.

```erlang
Client = vpndetection:new(),
ClientId = <<"your-client-id">>,
{ok, Device} = vpndetection:oauth_device_authorization(Client, ClientId,
    #{scope => <<"account.read apikeys.read apikeys.reveal">>}),
io:format("Open ~s and enter ~s~n", [maps:get(verification_uri, Device), maps:get(user_code, Device)]),
{ok, Token} = vpndetection:oauth_poll_device_token(Client, ClientId, Device),
Keyed = case Token of
    #{apikey := Key} -> vpndetection:new(#{api_key => Key});
    #{} -> error(no_api_key_picked)
end.
```

A refusal answers `{error, #{error_code := <<"access_denied">>}}` and a code that expired first `{error, #{error_code := <<"expired_token">>}}`. Client IDs are issued on request from support@vpndetection.io, and `vpndetection:oauth_revoke(Client, ClientId, maps:get(refresh_token, Token))` signs the machine out.

### Absent is not false

Fields your plan does not include are simply not in the result map. Absent means "not in your plan"; a present `false` means "we checked, and no".

```erlang
maps:get(is_hosting, Result, false).   % when you only want the flag
maps:is_key(is_hosting, Result).       % whether your plan carries the field
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" width="96"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
