# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Erlang Client Library

[![hex.pm](https://img.shields.io/hexpm/v/vpndetection.svg)](https://hex.pm/packages/vpndetection)
[![license](https://img.shields.io/hexpm/l/vpndetection.svg)](LICENSE)

The official Erlang client library for the [VPNDetection](https://vpndetection.io) API.

It tells you whether an IP address is a VPN, residential proxy, Tor node, relay or hosting server.

## Getting Started

```erlang
%% rebar.config
{deps, [vpndetection]}.
```

Requires Erlang/OTP 27 or newer. There are no runtime dependencies: everything the client needs is in OTP. From Elixir, add `{:vpndetection, "~> 3.19"}` to your `mix.exs` deps and call it as `:vpndetection`.

## Usage

**No API key needed to start.** Unlimited, the free plan, answers `ip`, `is_vpn`, Tor and relay detection, `is_anycast`, `is_bot` (whether an automated client, such as a search engine's crawler, uses the address), `hostname` (the reverse DNS name), country-level `location` and `asn` with the AS's country and RPKI status, with no daily or monthly cap, with a key or without one.

```erlang
Client = vpndetection:new(),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result).                        % true
maps:get(country, maps:get(location, Result)).   % the ISO 3166 country code
maps:get(name, maps:get(asn, Result)).           % who runs the announcing network
```

Every call answers `{ok, Term}` or `{error, Error}`. A client holds a cache, which is a process, so build one somewhere long lived and call `vpndetection:close(Client)` when you are finished with it.

### With an API key

Every paid plan answers every field: `is_hosting`, `is_cdn` and the four proxy flags as well, the carrier and satellite flags, the five service flags (SSH, SMTP, web, DNS resolver and BitTorrent), city-level `location`, the `company` and the `abuse` contact, the `bot` detail (whose bot uses the address, what it does and whether its operator vouches for the address), the `user_agent` verdict on a user agent you send with the lookup, and the provider (its ID and its name), confidence and last-seen detail behind each flag. The plans differ only in how many lookups they include, and a free account tries every field. Create a key in the [console](https://app.vpndetection.io), then pass it in:

```erlang
Client = vpndetection:new(#{api_key => <<"your-api-key">>}),

{ok, Result} = vpndetection:lookup(Client, <<"45.83.91.1">>),
maps:get(is_vpn, Result).                        % true
maps:get(is_hosting, Result).                    % true, on a paid plan
maps:get(provider, maps:get(vpn, Result)).       % <<"nordvpn">>, on a paid plan
maps:get(is_bot, Result).                        % whether a bot such as a crawler uses it
```

A detail map that is present but empty (`#{}`) means the flag above it is false. A populated one always carries every one of its keys.

### The user agent of the request you are deciding on

Pass the `User-Agent` of the request you are deciding on, and with every field (a paid plan, or the trial) the answer carries `user_agent`: the agent it names, what kind of client it says it is, and whether this address bears it out. A crawler claiming to be Googlebot from an address Google does not vouch for comes back `spoofed`:

```erlang
{ok, Result} = vpndetection:lookup(Client, <<"66.249.66.1">>,
                                   #{user_agent => <<"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)">>}),
#{agent := Agent, kind := Kind, verdict := Verdict} = maps:get(user_agent, Result).
%% Agent = <<"Googlebot">>, Kind = <<"bot">>,
%% Verdict = <<"verified">> | <<"spoofed">> | <<"unverifiable">> | <<"not_bot">>
```

`verified` means the agent's operator vouches for this address, `spoofed` that it does not (or the address posed as the bot before), `unverifiable` that the agent is a bot nothing can confirm, and `not_bot` that it is a browser, an app or a script. `user_agent` is absent when no agent was sent, on Unlimited, and on a private or reserved address, which is still answered locally. An empty agent is none, and one longer than 1024 characters is sent whole; the API reads its first 1024. An answer with an agent is cached apart from the address's plain answer and from another agent's. `my_ip/2` takes `user_agent` too, and `lookup_batch/3` takes `user_agents`, below.

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
maps:get(<<"name">>, Plan).        % <<"Max">>, what to show
maps:get(<<"key">>, Plan).         % <<"max">>, what to compare against
maps:get(<<"requests">>, Usage).   % 580
maps:get(<<"window_end">>, Usage). % when the allowance resets
```

Usage counts against the anniversary of your subscription on a paid plan, not the calendar month and not the billing period, and against the trial on the free plan; it is the same number a lookup is gated on. `hard_limit` is `null` on an uncapped plan, which is not the same as zero.

Show the plan's `name` and compare against its `key`: a plan's name can change, and its key never does. A value the API adds later to a plan's `tier`, a database's `standing` or `license_type`, a format or a download's `outcome` comes back as the binary it served, so check for the values you know rather than assuming the list is complete.

Note the key types differ: a lookup answers a map with ATOM keys, while the entitlement answers the decoded JSON with BINARY keys. `my_ip/2` and `my_entitlement/2` take a per-call options map.

### Batch lookup

Look up as many addresses as you like at once. Bogons and cached answers are handled locally, and everything else goes to the batch endpoint in chunks of up to 1000 addresses, in parallel. The batch endpoint needs a paid plan:

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

`user_agents` maps an address, written as it is in your list, to the user agent to send with it, and each of those addresses' answers carries its `user_agent` verdict as a single lookup's does:

```erlang
Results = vpndetection:lookup_batch(Client, [<<"66.249.66.1">>, <<"8.8.8.8">>],
                                    #{user_agents => #{<<"66.249.66.1">> => GooglebotAgent}}).
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
maps:get(is_bogon, Result).   % true, answered locally with no request
maps:get(is_vpn, Result).     % false
```

A locally computed answer is deliberately the widest shape the API serves, as the API answers a bogon: `is_bogon` is true, every other flag is present and false, and every detail map is present and empty. Do not read your plan's features off one.

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

`timeout_ms` bounds each attempt, body included, so a call that is retried can take longer in total. The client's values are defaults: `lookup/3`, `lookup_batch/3`, `my_ip/2` and `my_entitlement/2` each take `retries` and `timeout_ms` for that call alone, and `database_downloads/2` and every `oauth_*` function take `timeout_ms`. During a download it bounds the wait between chunks instead, because a whole transfer can take minutes.

### Database downloads

If your key carries the `db.download` scope, the licensed databases are available too:

```erlang
{ok, Datasets} = vpndetection:database_list(Client),
{ok, Url} = vpndetection:database_download_url(Client, <<"vpn_ip_extended_v1">>, mmdb),
{ok, Checksums} = vpndetection:database_checksums(Client, <<"vpn_ip_extended_v1">>, mmdb).
```

`database_download_url/3` returns a time-limited link rather than the bytes, so you choose how to transfer a file that can run to gigabytes. `vpndetection:database_formats()` lists the formats these take, for checking one that came from a flag or a config file, and `standings()` and `license_types()` list what a family's `standing` and `license_type` can be.

From 3.11.0, `database_download_url/4`, `database_download/5` and `database_download_bytes/4` take `#{build => Build}`, the build a `database.updated` webhook names, so the file is the one whose `sha256` the webhook carries rather than whatever is live by the time you ask. The shorter ones fetch the live build. A build is kept 7 days, and one pruned since is a `bad_request` with status 410:

```erlang
%% Dataset and Build from a database.updated webhook's data
{ok, Written} = vpndetection:database_download(Client, Dataset, mmdb, <<Dataset/binary, ".mmdb">>,
                                               #{build => Build}).
```

`database_downloads/2` lists your organization's recent download attempts, newest first, refusals included. A denial is what answers "it stopped working", and its absence answers nothing. `limit` defaults to 50 and the API clamps it to 200:

```erlang
{ok, Attempts} = vpndetection:database_downloads(Client, #{limit => 20}),

[io:format("~s ~s ~s~n", [maps:get(<<"created">>, A), maps:get(<<"dataset_id">>, A), maps:get(<<"outcome">>, A)])
 || A <- Attempts].
```

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

A refusal answers `{error, #{error_code := <<"access_denied">>}}` and a code that expired first `{error, #{error_code := <<"expired_token">>}}`. `vpndetection:oauth_revoke(Client, ClientId, maps:get(refresh_token, Token))` signs the machine out. Only a client we registered, such as our CLI, can use the device flow: an app of your own signs people in with the authorization code flow below.

### Sign in with OAuth (authorization code)

An app that can take a browser redirect signs the person in there instead, with a PKCE pair made for that one sign-in.

```erlang
Client = vpndetection:new(),
ClientId = <<"your-client-id">>,
RedirectUri = <<"http://127.0.0.1:8765/callback">>,
#{verifier := Verifier, challenge := Challenge} = vpndetection:oauth_create_pkce(),
{ok, Url} = vpndetection:oauth_authorization_url(Client, ClientId, RedirectUri, Challenge,
    #{scope => <<"apikeys.use">>, state => <<"your-state">>}),
%% Open Url in the browser. Its redirect to RedirectUri carries code and state.
{ok, Token} = vpndetection:oauth_exchange_authorization_code(Client, ClientId, Code, Verifier,
    RedirectUri).
```

Check that `state` came back as you sent it before you exchange `code`, which works once. The client ID can also be the https URL of a client metadata document your app serves, and such an app is never handed a key, so `Token` carries no `apikey`.

### Register a client

An app with no client ID, and no client metadata document to use as one, registers itself, then signs in with the `client_id` it gets back as the client ID for `oauth_authorization_url` and `oauth_exchange_authorization_code`:

```erlang
Client = vpndetection:new(),
{ok, Registration} = vpndetection:oauth_register(Client, [<<"http://127.0.0.1:8765/callback">>],
                                                 #{client_name => <<"Your App">>}).
```

Each redirect URI must be https on a public host name, or http on a loopback address, which then matches any port. Nothing is kept until a person approves the client, so an app with no client ID saved can simply register again.

### Absent is not false

Unlimited leaves out `is_hosting`, `is_cdn`, the four proxy flags, the carrier, satellite and service flags, `company`, `abuse` and `bot`, and of the detail behind each flag it answers only Tor's and relay's; a free-plan key's answer carries `trial_expired`, true once its trial is spent, and a paid key's carries `cap_reached`, true once its organization's overage cap is reached and the answer has Unlimited's. Fields your plan does not include are simply not in the result map. Absent means "not in your plan"; a present `false` means "we checked, and no".

```erlang
maps:get(is_hosting, Result, false).   % when you only want the flag
maps:is_key(is_hosting, Result).       % false on Unlimited: not in your plan
maps:get(trial_expired, Result, false). % true: a free-plan key's trial is spent
maps:get(cap_reached, Result, false).   % true: a paid key past its overage cap
```

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
