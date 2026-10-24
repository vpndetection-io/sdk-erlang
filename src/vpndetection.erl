%% @doc The official Erlang client for the VPNDetection API.
%%
%% Build a client once with {@link new/1}, pass the term around, and release it
%% with {@link close/1}. Every call answers `{ok, Term}' or `{error, Error}';
%% nothing here raises for a failure the API can report.
%%
%% <b>Absent is not false.</b> A result is a map whose plan-gated keys are simply
%% MISSING when your plan does not include them, which is a different answer from
%% the key being present and `false'. Use `maps:get(is_hosting, Result,
%% undefined)' or `maps:find(is_hosting, Result)' when the distinction matters,
%% and `maps:get(is_hosting, Result, false)' when it does not.
-module(vpndetection).

-export([new/0, new/1, close/1]).
-export([is_bogon/1, is_bogon/2]).
-export([lookup/2, lookup/3, lookup_batch/2, lookup_batch/3]).
-export([my_ip/1, my_ip/2, my_entitlement/1, my_entitlement/2]).
-export([database_list/1, database_metadata/2, database_checksums/3,
         database_downloads/1, database_downloads/2, database_download_url/3,
         database_download/4, database_download_bytes/3]).
-export([database_formats/0, standings/0, license_types/0]).
-export([oauth_metadata/1, oauth_metadata/2, oauth_device_authorization/2,
         oauth_device_authorization/3, oauth_exchange_device_code/3, oauth_exchange_device_code/4,
         oauth_exchange_refresh_token/3, oauth_exchange_refresh_token/4, oauth_revoke/3, oauth_revoke/4,
         oauth_poll_device_token/3, oauth_poll_device_token/4]).
-export([oauth_authorization_url/4, oauth_authorization_url/5, oauth_exchange_authorization_code/5,
         oauth_exchange_authorization_code/6, oauth_create_pkce/0, oauth_pkce_challenge/1]).

-export_type([client/0, options/0, address/0, lookup_options/0, batch_options/0,
              downloads_options/0, format/0]).
-export_type([oauth_options/0, device_authorization_options/0, authorization_url_options/0]).

-define(DEFAULT_BASE_URL, <<"https://api.vpndetection.io">>).
-define(DEFAULT_CONCURRENCY, 8).
-define(DEFAULT_RETRIES, 2).
-define(DEFAULT_CACHE_MAX, 10000).
-define(DEFAULT_CACHE_TTL_MS, 3600000).
-define(DEFAULT_TIMEOUT_MS, 30000).
%% The longest `timeout_ms' the transport can wait on: httpc's timer and a
%% `receive ... after' both raise `timeout_value' past 2^32 - 1 ms (~49.7 days).
-define(MAX_TIMEOUT_MS, 4294967295).
-define(BATCH_TAG, '$vpndetection_batch').
%% The most addresses POST /batch takes in one call; a larger batch is sent in
%% chunks of this size.
-define(BATCH_MAX, 1000).
%% What a lookup answer must be, whatever the plan: `ip' and `is_vpn' always,
%% and every other member typed wherever it is present.
-define(LOOKUP, {whole, lookup_shape()}).

-opaque client() :: #{
    base_url := binary(),
    api_key := binary() | undefined,
    cache := vpndetection_cache:cache() | undefined,
    concurrency := pos_integer(),
    retries := non_neg_integer(),
    timeout_ms := pos_integer() | infinity,
    user_agent := binary(),
    http := vpndetection_http:http_fun()
}.

-type options() :: #{
    api_key => binary() | string() | false | nil,
    base_url => binary() | string(),
    cache => #{max => pos_integer(), ttl_ms => pos_integer()} | false,
    concurrency => pos_integer(),
    retries => non_neg_integer(),
    timeout_ms => pos_integer() | infinity,
    http => vpndetection_http:http_fun()
}.

%% An address as text, or as the tuple `inet' and Cowboy hand one over as.
-type address() :: binary() | string() | inet:ip_address().
-type lookup_options() :: #{retries => non_neg_integer(), timeout_ms => pos_integer() | infinity}.
-type batch_options() :: #{retries => non_neg_integer(), concurrency => pos_integer(),
                           timeout_ms => pos_integer() | infinity}.
-type downloads_options() :: #{limit => pos_integer(), timeout_ms => pos_integer() | infinity}.
-type format() :: csvgz | mmdb.
%% The same set at runtime, because `format()' checks nothing once compiled.
-define(FORMATS, [csvgz, mmdb]).

-type oauth_options() :: #{timeout_ms => pos_integer() | infinity}.
-type device_authorization_options() :: #{scope => binary() | string(),
                                          resource => binary() | string(),
                                          timeout_ms => pos_integer() | infinity}.
-type authorization_url_options() :: #{scope => binary() | string(), state => binary() | string(),
                                       resource => binary() | string()}.

-spec new() -> client().
new() ->
    new(#{}).

%% @doc Build a client.
%%
%% `api_key' is optional: without one you get the free tier, which answers `ip'
%% and `is_vpn' and allows 1000 requests per day per source address. An empty or
%% blank key is no key, and so are `false', which is what `os:getenv/1' answers
%% for a variable that is not set, and `nil', Elixir's `System.get_env/1' answer
%% for one. The key is trimmed, so one read from a file
%% with its newline works; one still holding a control character raises
%% `{badarg, {api_key, control_character}}', naming the cause and not the key.
%%
%% `timeout_ms' is milliseconds from 1 to 4294967295, or `infinity' for no bound,
%% and `retries' an integer of 0 or more; anything else raises `badarg' here
%% rather than failing every call.
%%
%% The cache is per client and never shared, because two clients holding
%% different keys are on different plans and so entitled to different fields.
%% Unless `cache' is `false' this starts a process linked to the caller, which
%% ends when the caller does, so build clients somewhere long lived and `close/1'
%% them when you are done.
-spec new(options()) -> client().
new(Options) ->
    TimeoutMs = maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
    case valid_timeout(TimeoutMs) of
        true -> ok;
        false -> erlang:error({badarg, {timeout_ms, TimeoutMs}})
    end,
    Retries = maps:get(retries, Options, ?DEFAULT_RETRIES),
    case valid_retries(Retries) of
        true -> ok;
        false -> erlang:error({badarg, {retries, Retries}})
    end,
    Key = api_key(maps:get(api_key, Options, undefined)),
    case maps:is_key(http, Options) of
        false -> vpndetection_http:ensure_ready();
        true -> ok
    end,
    #{
        base_url => trim_slashes(bin(maps:get(base_url, Options, ?DEFAULT_BASE_URL))),
        api_key => Key,
        cache => cache(maps:get(cache, Options, #{})),
        concurrency => maps:get(concurrency, Options, ?DEFAULT_CONCURRENCY),
        retries => Retries,
        timeout_ms => TimeoutMs,
        user_agent => user_agent(),
        http => maps:get(http, Options, vpndetection_http:httpc_fun())
    }.

%% @doc Release the client's cache. Safe to call on a client that has none.
-spec close(client()) -> ok.
close(#{cache := undefined}) ->
    ok;
close(#{cache := Cache}) ->
    vpndetection_cache:stop(Cache).

%% @doc Whether an address is private, loopback, link-local, documentation,
%% multicast or otherwise not routable, including the IPv6 equivalents and the
%% 6to4 and Teredo ranges.
%%
%% These are the addresses {@link lookup/2} answers locally, so they cost no
%% request and no quota. Usable without a client.
-spec is_bogon(binary() | string()) -> boolean().
is_bogon(Ip) ->
    vpndetection_bogon:is_bogon(Ip).

%% @doc {@link is_bogon/1}, reachable from a client you already hold.
-spec is_bogon(client(), binary() | string()) -> boolean().
is_bogon(_Client, Ip) ->
    vpndetection_bogon:is_bogon(Ip).

-spec lookup(client(), address()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
lookup(Client, Ip) ->
    lookup(Client, Ip, #{}).

%% @doc Classify one address.
%%
%% `Ip' is text, or a tuple as `inet:peername/1' and Cowboy's `peer' give it. A
%% bogon is answered locally and never reaches the network. Everything else is
%% served, then cached for this client alone.
%%
%% `Options' overrides the client's `retries' and `timeout_ms' for this call
%% alone. `timeout_ms' bounds each attempt, so a retried call can take longer in
%% total.
-spec lookup(client(), address(), lookup_options()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
lookup(Client, Ip, Options) ->
    checked(Options, fun() ->
        %% Judged, cached and sent as the IPv4 address it carries, if it is mapped.
        Addr = vpndetection_bogon:unmapped(address(Ip)),
        case vpndetection_bogon:is_bogon(Addr) of
            true -> {ok, vpndetection_result:bogon(Addr)};
            false -> served(Client, Addr, Options)
        end
    end).

-spec my_ip(client()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
my_ip(Client) ->
    my_ip(Client, #{}).

%% @doc Classify the address this client is calling from.
%%
%% The same answer {@link lookup/2} would give for that address, at the same cost
%% against your allowance. The address is the one our edge observed, so a call
%% made through a proxy or a VPN reports the exit it left through - usually the
%% point of asking.
%%
%% Deliberately NOT cached. The cache is keyed by address, and which address this
%% is IS the question: a machine that moves between networks would otherwise be
%% told where it used to be.
-spec my_ip(client(), lookup_options()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
my_ip(Client, Options) ->
    checked(Options, fun() ->
        Retries = maps:get(retries, Options, maps:get(retries, Client)),
        case vpndetection_http:get_json(bound(Client, Options), <<"/myip">>, [], Retries, ?LOOKUP) of
            {ok, Body} -> {ok, vpndetection_result:from_wire(Body)};
            {error, Error} -> {error, Error}
        end
    end).

-spec my_entitlement(client()) -> {ok, map()} | {error, vpndetection_error:error()}.
my_entitlement(Client) ->
    my_entitlement(Client, #{}).

%% @doc What this client's key is entitled to, and how much of it has been used.
%%
%% Named for what it answers rather than `me', which sits one letter from
%% {@link my_ip/1} and means something quite different: one is which address you
%% are calling FROM, the other is what the key you are calling WITH may spend.
%%
%% Unlike a lookup there is no useful unauthenticated answer, so a client built
%% without an API key gets an unauthorized error rather than a partial one.
%%
%% Usage counts against the ALLOWANCE WINDOW - the anniversary of the
%% subscription, not the calendar month and not the billing period - and it is
%% the same number a lookup is gated on. `hard_limit' is `null' when we never
%% stop serving, which is not the same as a limit of zero.
%%
%% Deliberately NOT cached: the whole point is what has been spent, and a cached
%% answer is a wrong one within seconds of the next request.
-spec my_entitlement(client(), lookup_options()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
my_entitlement(Client, Options) ->
    checked(Options, fun() ->
        Retries = maps:get(retries, Options, maps:get(retries, Client)),
        Shape = {whole, entitlement_shape()},
        vpndetection_http:get_json(bound(Client, Options), <<"/api/v1/entitlement">>, [], Retries, Shape)
    end).

-spec lookup_batch(client(), [address()]) ->
    #{binary() => {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}}.
lookup_batch(Client, Ips) ->
    lookup_batch(Client, Ips, #{}).

%% @doc Classify many addresses in as few requests as possible.
%%
%% Bogons are answered locally and cached answers are reused; everything else
%% goes to the batch endpoint in chunks of up to 1000 addresses, with at most
%% `concurrency' chunks in flight. Keyed by address rather than positional, so
%% duplicates in the input collapse to a single entry and the caller never has
%% to line two lists up. An address that fails carries its `{error, Error}' as
%% its value, so one bad entry cannot lose the rest of the answers: the API
%% reports a per-entry failure with the status the single lookup would have
%% answered, and a chunk that fails as a whole marks every address in it.
%% Erlang maps have no insertion order, so the result is a set of keys rather
%% than a sequence. An address given as a tuple is keyed by its text.
%%
%% `concurrency', `retries' and `timeout_ms' are overridable here, per call, so
%% one large batch does not need a second client built to widen it. There is no
%% cap on how many addresses one call takes; chunking them is this function's job.
-spec lookup_batch(client(), [address()], batch_options()) ->
    #{binary() => {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}}.
lookup_batch(Client, Ips, Options) ->
    Asked = lists:uniq([address(Ip) || Ip <- Ips]),
    %% An IPv4-mapped address is sent as the address it carries, once however
    %% many of its spellings were asked, and answered under each one asked.
    Unique = lists:uniq([vpndetection_bogon:unmapped(Ip) || Ip <- Asked]),
    case {maps:get(concurrency, Options, maps:get(concurrency, Client)), check_options(Options)} of
        %% A timeout no attempt can meet, or retries that are no count, fail every
        %% address the same way, before any request.
        {_, {error, Error}} ->
            maps:from_list([{Ip, {error, Error}} || Ip <- Asked]);
        {Concurrency, ok} when is_integer(Concurrency), Concurrency >= 1 ->
            Answers = batch(Client, Unique, Options, Concurrency),
            maps:from_list([{Ip, maps:get(vpndetection_bogon:unmapped(Ip), Answers)} || Ip <- Asked]);
        %% A dispatcher that may run nothing waits for ever, so this is the
        %% caller's mistake to hear about at once.
        {Refused, ok} ->
            Message = iolist_to_binary(io_lib:format("concurrency must be at least 1, not ~p", [Refused])),
            Error = #{kind => bad_request, retryable => false, message => Message},
            maps:from_list([{Ip, {error, Error}} || Ip <- Asked])
    end.

%% @doc Every format a dataset file is published in: the values `format()' takes,
%% for checking one that came from a flag or a config file.
-spec database_formats() -> [format()].
database_formats() ->
    ?FORMATS.

%% @doc Every value a family's `&lt;&lt;"standing"&gt;&gt;' takes in {@link database_list/1}.
-spec standings() -> [binary()].
standings() ->
    [<<"expired">>, <<"licensed">>, <<"unlicensed">>].

%% @doc Every value a family's `&lt;&lt;"license_type"&gt;&gt;' takes when it is not `null'.
-spec license_types() -> [binary()].
license_types() ->
    [<<"evaluation">>, <<"standard">>, <<"redistribute">>].

%% @doc The dataset FAMILIES your organization is licensed to download.
%%
%% A license covers a family (`vpn_ip'), while a download names one of its
%% versions (`vpn_ip_v1'), so the ids {@link database_download/4} and
%% {@link database_checksums/3} take come from a family's `&lt;&lt;"versions"&gt;&gt;'
%% rather than from the family itself.
%%
%% Every database response keeps its wire keys as BINARIES. The lookup result is
%% the one place a spec-defined name becomes an atom, because the dataset
%% metadata is keyed by dataset column names, which are the server's to choose
%% and would otherwise fill the atom table.
-spec database_list(client()) -> {ok, [map()]} | {error, vpndetection_error:error()}.
database_list(Client) ->
    get_json(Client, <<"/api/v1/database/list">>, [], {<<"databases">>, {list, database_shape()}}).

%% @doc What is inside one dataset: schema, samples, row count, sizes.
-spec database_metadata(client(), binary() | string()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
database_metadata(Client, Id) ->
    get_json(Client, <<"/api/v1/database/metadata">>, [{<<"id">>, bin(Id)}], {whole, metadata_shape()}).

%% @doc Every digest published for one dataset file.
%%
%% The whole set, not one algorithm: which digests a dataset publishes is the
%% API's choice rather than ours, and they arrive nested under `checksums'.
-spec database_checksums(client(), binary() | string(), format()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
database_checksums(Client, Id, Format) ->
    case format_name(Format) of
        {ok, Name} ->
            Query = [{<<"id">>, bin(Id)}, {<<"format">>, Name}],
            case get_json(Client, <<"/api/v1/database/checksum">>, Query, {whole, checksum_shape()}) of
                {ok, #{<<"checksums">> := Checksums}} -> {ok, Checksums};
                {error, Error} -> {error, Error}
            end;
        {error, Error} ->
            {error, Error}
    end.

-spec database_downloads(client()) -> {ok, [map()]} | {error, vpndetection_error:error()}.
database_downloads(Client) ->
    database_downloads(Client, #{}).

%% @doc Your organization's recent download attempts, newest first.
%%
%% Refusals are listed too: a denial is what answers "it stopped working", and
%% its absence answers nothing. `limit' defaults to 50 and the API clamps it
%% to 200. `timeout_ms' bounds each attempt of this call alone, so a retried
%% call can take longer in total.
-spec database_downloads(client(), downloads_options()) ->
    {ok, [map()]} | {error, vpndetection_error:error()}.
database_downloads(Client, Options) ->
    Query = case maps:find(limit, Options) of
        {ok, Limit} -> [{<<"limit">>, integer_to_binary(Limit)}];
        error -> []
    end,
    checked(Options, fun() ->
        get_json(bound(Client, Options), <<"/api/v1/database/downloads">>, Query, {<<"downloads">>, {list, download_shape()}})
    end).

%% @doc The time-limited URL for one dataset file.
%%
%% The URL is returned rather than the bytes, so the caller decides how to
%% transfer a file that routinely runs to gigabytes. The link authorizes the
%% START of a transfer, so one already running is not interrupted when it lapses.
-spec database_download_url(client(), binary() | string(), format()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
database_download_url(Client, Id, Format) ->
    case format_name(Format) of
        {ok, Name} ->
            Query = [{<<"id">>, bin(Id)}, {<<"format">>, Name}],
            vpndetection_http:get_redirect(Client, <<"/api/v1/database/download">>, Query,
                                           maps:get(retries, Client));
        {error, Error} ->
            {error, Error}
    end.

%% @doc Download one dataset file to `Path', and answer how many bytes landed.
%%
%% The transfer is streamed, so nothing beyond a single chunk is ever held in
%% memory whatever the dataset weighs. The bytes go to a neighboring `.part' file
%% that is renamed only once the whole body has arrived: a transfer that dies
%% halfway leaves neither a truncated file that reads as a complete dataset nor a
%% `.part' for the next attempt to append to.
%%
%% The client's `timeout_ms' bounds the wait between chunks here rather than the
%% whole transfer, because a deadline that suits a lookup is the wrong one for a
%% gigabyte while a stalled transfer is stalled at any size.
-spec database_download(client(), binary() | string(), format(), binary() | string()) ->
    {ok, non_neg_integer()} | {error, vpndetection_error:error()}.
database_download(Client, Id, Format, Path) ->
    Dest = bin(Path),
    Partial = <<Dest/binary, ".part">>,
    case file:open(Partial, [write, binary, raw]) of
        {ok, Fd} -> to_file(Client, Id, Format, Dest, Partial, Fd);
        {error, Reason} -> {error, io_error(Partial, Reason)}
    end.

%% @doc Download one dataset file and hand back its bytes.
%%
%% This holds the ENTIRE file in memory, and the catalog spans five orders of
%% magnitude, from `cdn_ip_v1' at 10 KB to `resproxy_ip_90d_v1' at 1.79 GB, so
%% reach for it at the small end and use {@link database_download/4} for anything
%% you have not measured. It transfers over exactly the same streamed path, so
%% the bytes are the ones {@link database_download/4} would have written.
-spec database_download_bytes(client(), binary() | string(), format()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
database_download_bytes(Client, Id, Format) ->
    Sink = #{fold => fun(Chunk, Chunks) -> {ok, [Chunk | Chunks]} end, acc => []},
    case transfer(Client, Id, Format, Sink) of
        {ok, #{acc := Chunks}} -> {ok, iolist_to_binary(lists:reverse(Chunks))};
        {error, Error} -> {error, Error}
    end.

-spec oauth_metadata(client()) ->
    {ok, vpndetection_oauth:metadata()} | {error, vpndetection_error:error()}.
oauth_metadata(Client) ->
    oauth_metadata(Client, #{}).

%% @doc The authorization server's discovery document.
%%
%% Every `oauth_*' call sends NO credential, whatever the client was built with,
%% and works the same on a client built without a key. `timeout_ms' in `Options'
%% bounds each attempt of this call alone.
-spec oauth_metadata(client(), oauth_options()) ->
    {ok, vpndetection_oauth:metadata()} | {error, vpndetection_error:error()}.
oauth_metadata(Client, Options) ->
    checked(Options, fun() -> vpndetection_oauth:metadata(Client, Options) end).

-spec oauth_device_authorization(client(), binary() | string()) ->
    {ok, vpndetection_oauth:device_authorization()} | {error, vpndetection_error:error()}.
oauth_device_authorization(Client, ClientId) ->
    oauth_device_authorization(Client, ClientId, #{}).

%% @doc Start a device sign-in: show the person `user_code' and
%% `verification_uri', then call {@link oauth_poll_device_token/3}.
%%
%% Client IDs are issued on request from support@vpndetection.io. `scope' is one
%% space-delimited string, sent as given; the server grants what the client may
%% ask for and silently drops the rest.
-spec oauth_device_authorization(client(), binary() | string(), device_authorization_options()) ->
    {ok, vpndetection_oauth:device_authorization()} | {error, vpndetection_error:error()}.
oauth_device_authorization(Client, ClientId, Options) ->
    Extra = [{atom_to_binary(Name), bin(Value)} || Name <- [scope, resource],
                                                   {ok, Value} <- [maps:find(Name, Options)]],
    checked(Options, fun() -> vpndetection_oauth:device_authorization(Client, bin(ClientId), Extra, Options) end).

-spec oauth_exchange_device_code(client(), binary() | string(), binary() | string()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_device_code(Client, ClientId, DeviceCode) ->
    oauth_exchange_device_code(Client, ClientId, DeviceCode, #{}).

%% @doc Exchange a device code for tokens, once. Until the person approves, this
%% answers `{error, #{error_code := <<"authorization_pending">>}}';
%% {@link oauth_poll_device_token/3} is the loop that waits for them.
%%
%% Never retried: the server spends the code when it answers, so a retry after a
%% lost success could only fail and lose the tokens. The answer carries
%% `apikey_id' and `apikey' when the person picked a key.
-spec oauth_exchange_device_code(client(), binary() | string(), binary() | string(), oauth_options()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_device_code(Client, ClientId, DeviceCode, Options) ->
    checked(Options, fun() -> vpndetection_oauth:exchange_device_code(Client, bin(ClientId), bin(DeviceCode), Options) end).

-spec oauth_exchange_refresh_token(client(), binary() | string(), binary() | string()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_refresh_token(Client, ClientId, RefreshToken) ->
    oauth_exchange_refresh_token(Client, ClientId, RefreshToken, #{}).

%% @doc Exchange a refresh token for a new pair. The token presented is spent, so
%% keep the `refresh_token' this answers. Never retried; the answer may name the
%% key in `apikey_id' but never carries `apikey'.
-spec oauth_exchange_refresh_token(client(), binary() | string(), binary() | string(),
                                   oauth_options()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_refresh_token(Client, ClientId, RefreshToken, Options) ->
    checked(Options, fun() ->
        vpndetection_oauth:exchange_refresh_token(Client, bin(ClientId), bin(RefreshToken), Options)
    end).

-spec oauth_revoke(client(), binary() | string(), binary() | string()) ->
    ok | {error, vpndetection_error:error()}.
oauth_revoke(Client, ClientId, Token) ->
    oauth_revoke(Client, ClientId, Token, #{}).

%% @doc Revoke an access or a refresh token. A refresh token ends the whole grant
%% and every token it issued, which is how a machine signs out.
-spec oauth_revoke(client(), binary() | string(), binary() | string(), oauth_options()) ->
    ok | {error, vpndetection_error:error()}.
oauth_revoke(Client, ClientId, Token, Options) ->
    checked(Options, fun() -> vpndetection_oauth:revoke(Client, bin(ClientId), bin(Token), Options) end).

-spec oauth_poll_device_token(client(), binary() | string(), vpndetection_oauth:device_authorization()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_poll_device_token(Client, ClientId, Device) ->
    oauth_poll_device_token(Client, ClientId, Device, #{}).

%% @doc Wait for the person to approve a device sign-in, and answer its tokens.
%%
%% Waits the device's `interval' seconds before EVERY exchange, the first
%% included, and five seconds longer for good each time the server answers
%% `slow_down'. A refusal answers `error_code' `<<"access_denied">>'; an expired
%% code `<<"expired_token">>', with no `status' when the device's `expires_in'
%% ran out here first. Any other failure, a timeout or an outage included, ends
%% the wait unchanged; calling again with the same device is safe until it expires.
%%
%% It blocks the calling process until one of those outcomes. There is no
%% cancellation handle, so run it in a process you can kill. `timeout_ms' bounds
%% each exchange, never the whole wait.
-spec oauth_poll_device_token(client(), binary() | string(), vpndetection_oauth:device_authorization(),
                              oauth_options()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_poll_device_token(Client, ClientId, Device, Options) ->
    checked(Options, fun() -> vpndetection_oauth:poll_device_token(Client, bin(ClientId), Device, Options) end).

-spec oauth_authorization_url(client(), binary() | string(), binary() | string(), binary() | string()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
oauth_authorization_url(Client, ClientId, RedirectUri, CodeChallenge) ->
    oauth_authorization_url(Client, ClientId, RedirectUri, CodeChallenge, #{}).

%% @doc The URL to open in the person's browser for the authorization code flow,
%% from the `challenge' of {@link oauth_create_pkce/0}. Makes no request.
%%
%% Once they decide, the server redirects to `RedirectUri' with a `code' for
%% {@link oauth_exchange_authorization_code/5} and the `state' given here, or with
%% an `error'. `scope', `state' and `resource' are left out when not given or
%% empty. Every value is percent-encoded over UTF-8, leaving only
%% `A-Z a-z 0-9 - . _ ~' literal; an empty required value, or one with no UTF-8
%% form, answers `bad_request'. The client ID can also be the https URL of a
%% client metadata document the app serves.
-spec oauth_authorization_url(client(), binary() | string(), binary() | string(), binary() | string(),
                              authorization_url_options()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
oauth_authorization_url(Client, ClientId, RedirectUri, CodeChallenge, Options) ->
    Required = [{<<"client_id">>, ClientId}, {<<"redirect_uri">>, RedirectUri},
                {<<"code_challenge">>, CodeChallenge}],
    Optional = [{atom_to_binary(Name), Value} || Name <- [scope, state, resource],
                                                 {ok, Value} <- [maps:find(Name, Options)]],
    vpndetection_oauth:authorization_url(Client, Required, Optional).

-spec oauth_exchange_authorization_code(client(), binary() | string(), binary() | string(),
                                        binary() | string(), binary() | string()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_authorization_code(Client, ClientId, Code, CodeVerifier, RedirectUri) ->
    oauth_exchange_authorization_code(Client, ClientId, Code, CodeVerifier, RedirectUri, #{}).

%% @doc Exchange the `code' a sign-in's redirect brought back for tokens, once.
%% `CodeVerifier' is the `verifier' whose challenge went into the authorization
%% URL, and `RedirectUri' that URL's, exactly.
%%
%% Never retried: the server spends the code on first read, before it checks the
%% verifier, so a retry could only be refused.
-spec oauth_exchange_authorization_code(client(), binary() | string(), binary() | string(),
                                        binary() | string(), binary() | string(), oauth_options()) ->
    {ok, vpndetection_oauth:token_response()} | {error, vpndetection_error:error()}.
oauth_exchange_authorization_code(Client, ClientId, Code, CodeVerifier, RedirectUri, Options) ->
    checked(Options, fun() ->
        vpndetection_oauth:exchange_authorization_code(Client, bin(ClientId), bin(Code), bin(CodeVerifier),
                                                       bin(RedirectUri), Options)
    end).

%% @doc A fresh PKCE pair for one sign-in: 32 bytes from `crypto''s secure random
%% source as a 43-character base64url `verifier', its `S256' `challenge', and the
%% `method'. The challenge goes into the authorization URL, the verifier only to
%% the exchange.
-spec oauth_create_pkce() -> vpndetection_oauth:pkce().
oauth_create_pkce() ->
    vpndetection_oauth:create_pkce().

%% @doc The `S256' challenge for a PKCE verifier: its SHA-256, as unpadded base64url.
-spec oauth_pkce_challenge(binary() | string()) -> binary().
oauth_pkce_challenge(Verifier) ->
    vpndetection_oauth:pkce_challenge(bin(Verifier)).

to_file(Client, Id, Format, Dest, Partial, Fd) ->
    Sink = #{acc => Fd, fold => fun(Chunk, Handle) ->
        case file:write(Handle, Chunk) of
            ok -> {ok, Handle};
            {error, Reason} -> {error, message(Partial, Reason)}
        end
    end},
    Transferred = transfer(Client, Id, Format, Sink),
    Closed = file:close(Fd),
    case {Transferred, Closed} of
        {{ok, #{written := Written}}, ok} ->
            rename(Partial, Dest, Written);
        %% A close that fails is a write that failed: with the file gone the
        %% count says nothing, so this is a failure rather than a short success.
        {{ok, _}, {error, Reason}} ->
            discard(Partial),
            {error, io_error(Dest, Reason)};
        {{error, Error}, _} ->
            discard(Partial),
            {error, Error}
    end.

%% The 302 is followed as a SECOND request that carries no credential: the
%% presigned link authorizes itself, and forwarding the API key would hand it to
%% a host with no business holding it.
transfer(Client, Id, Format, Sink) ->
    case database_download_url(Client, Id, Format) of
        {ok, Url} -> vpndetection_http:get_stream(Client, Url, Sink, maps:get(retries, Client));
        {error, Error} -> {error, Error}
    end.

rename(Partial, Dest, Written) ->
    case file:rename(Partial, Dest) of
        ok ->
            {ok, Written};
        {error, Reason} ->
            discard(Partial),
            {error, io_error(Dest, Reason)}
    end.

discard(Partial) ->
    _ = file:delete(Partial),
    ok.

io_error(Path, Reason) ->
    #{kind => io, retryable => false, message => message(Path, Reason)}.

message(Path, Reason) ->
    iolist_to_binary([Path, ": ", file:format_error(Reason)]).

%% Without a cache nothing is shared, since every lookup is then served.
served(#{cache := undefined} = Client, Addr, Options) ->
    fetch(Client, Addr, Options);
served(#{cache := Cache} = Client, Addr, Options) ->
    case vpndetection_cache:get(Cache, Addr) of
        {ok, Result} -> {ok, Result};
        miss -> shared(Client, Cache, Addr, Options)
    end.

%% Concurrent misses for one address share one request, a lookup's or the batch
%% chunk carrying it: the first to board the address leads, under its own
%% options, and every other caller awaits its answer. A leader that dies before
%% answering sends its waiters back to ask again rather than failing them.
shared(Client, Cache, Addr, Options) ->
    Ref = make_ref(),
    case vpndetection_cache:board(Cache, [Addr], Ref) of
        [{Addr, {ok, Result}}] ->
            {ok, Result};
        [{Addr, lead}] ->
            Answer = leading(Cache, [Addr], fun() -> fetch(Client, Addr, Options) end),
            %% Errors are never cached: a 500 or a rate limit says nothing about the address.
            vpndetection_cache:land(Cache, [{Addr, Answer}]),
            Answer;
        [{Addr, wait}] ->
            case vpndetection_cache:await(Cache, Ref, [Addr]) of
                #{Addr := retry} -> shared(Client, Cache, Addr, Options);
                #{Addr := Answer} -> Answer
            end
    end.

%% Runs a leader's requests, taking what it leads off the board if they raise,
%% so a caller that catches the exception cannot leave its waiters hanging.
leading(Cache, Led, Send) ->
    try
        Send()
    catch
        Class:Reason:Stack ->
            vpndetection_cache:abandon(Cache, Led),
            erlang:raise(Class, Reason, Stack)
    end.

fetch(Client, Addr, Options) ->
    Path = <<"/", (vpndetection_http:escape(Addr))/binary>>,
    Retries = maps:get(retries, Options, maps:get(retries, Client)),
    case vpndetection_http:get_json(bound(Client, Options), Path, [], Retries, ?LOOKUP) of
        {ok, Body} -> {ok, vpndetection_result:from_wire(Body)};
        {error, Error} -> {error, Error}
    end.

cached(#{cache := undefined}, _Addr) ->
    miss;
cached(#{cache := Cache}, Addr) ->
    vpndetection_cache:get(Cache, Addr).

batch(Client, Unique, Options, Concurrency) ->
    {Answered, Pending} = lists:foldl(fun(Ip, {Acc, Rest}) ->
        case local(Client, Ip) of
            {ok, Result} -> {Acc#{Ip => {ok, Result}}, Rest};
            miss -> {Acc, [Ip | Rest]}
        end
    end, {#{}, []}, Unique),
    maps:merge(Answered, rounds(Client, lists:reverse(Pending), Options, Concurrency, #{})).

%% Every address the batch must ask is boarded BEFORE its chunks are built: the
%% ones it leads are sent, landing chunk by chunk, so a lookup arriving meanwhile
%% awaits the chunk carrying its address; the ones a lookup already has in the
%% air are awaited rather than sent again. An address whose leader died is
%% boarded again in the next round.
rounds(_Client, [], _Options, _Concurrency, Acc) ->
    Acc;
rounds(#{cache := undefined} = Client, Ips, Options, Concurrency, Acc) ->
    maps:merge(Acc, send(Client, Ips, Options, Concurrency, fun(_Chunk, _Answers) -> ok end));
rounds(#{cache := Cache} = Client, Ips, Options, Concurrency, Acc) ->
    Ref = make_ref(),
    Boarded = vpndetection_cache:board(Cache, Ips, Ref),
    Hits = maps:from_list([{Ip, Hit} || {Ip, {ok, _} = Hit} <- Boarded]),
    Led = [Ip || {Ip, lead} <- Boarded],
    Land = fun(Chunk, Answers) -> vpndetection_cache:land(Cache, [{Ip, maps:get(Ip, Answers)} || Ip <- Chunk]) end,
    Sent = leading(Cache, Led, fun() -> send(Client, Led, Options, Concurrency, Land) end),
    Awaited = vpndetection_cache:await(Cache, Ref, [Ip || {Ip, wait} <- Boarded]),
    {Again, Answers} = maps:fold(fun
        (Ip, retry, {A, D}) -> {[Ip | A], D};
        (Ip, Answer, {A, D}) -> {A, D#{Ip => Answer}}
    end, {[], #{}}, Awaited),
    rounds(Client, lists:reverse(Again), Options, Concurrency,
           maps:merge(maps:merge(maps:merge(Acc, Hits), Sent), Answers)).

%% The addresses sent as chunks, each chunk handed to `Land' as it completes.
send(Client, Ips, Options, Concurrency, Land) ->
    ByChunk = dispatch(fun(Chunk) -> lookup_chunk(Client, Chunk, Options) end, Land,
                       chunk(Ips, ?BATCH_MAX), Concurrency, #{}, #{}, #{}),
    maps:fold(fun(_Chunk, Answers, Acc) -> maps:merge(Acc, Answers) end, #{}, ByChunk).

%% Bounded fan-out. At most `Limit' workers are alive at any moment, so the
%% concurrency setting is the number of requests actually in flight rather than
%% a hint. spawn_monitor rather than spawn, rather than waiting on results alone,
%% so a worker that dies without answering cannot hang the batch.
dispatch(Fun, Land, [Item | Rest], Limit, Pending, Done, Acc) when map_size(Pending) < Limit ->
    Parent = self(),
    {Pid, _Mon} = spawn_monitor(fun() -> Parent ! {?BATCH_TAG, self(), Fun(Item)} end),
    dispatch(Fun, Land, Rest, Limit, Pending#{Pid => Item}, Done, Acc);
dispatch(_Fun, _Land, [], _Limit, Pending, _Done, Acc) when map_size(Pending) =:= 0 ->
    Acc;
dispatch(Fun, Land, Queue, Limit, Pending, Done, Acc) ->
    receive
        {?BATCH_TAG, Pid, Result} ->
            dispatch(Fun, Land, Queue, Limit, Pending, Done#{Pid => Result}, Acc);
        %% Only a worker's: the caller's own monitors are not this batch's to consume.
        {'DOWN', _Mon, process, Pid, Reason} when is_map_key(Pid, Pending) ->
            %% Signals between a pair of processes keep their order, so a result
            %% sent before the worker exited is already in Done by now.
            Item = maps:get(Pid, Pending),
            Answers = case maps:find(Pid, Done) of
                {ok, Result} -> Result;
                error -> maps:from_list([{Ip, {error, worker_died(Reason)}} || Ip <- Item])
            end,
            Land(Item, Answers),
            dispatch(Fun, Land, Queue, Limit, maps:remove(Pid, Pending), maps:remove(Pid, Done),
                     Acc#{Item => Answers})
    end.

worker_died(Reason) ->
    #{kind => network, retryable => false,
      message => iolist_to_binary(io_lib:format("lookup worker exited: ~p", [Reason]))}.

%% A bogon or a cached answer costs no request; `miss' is what goes to the API.
local(Client, Ip) ->
    case vpndetection_bogon:is_bogon(Ip) of
        true -> {ok, vpndetection_result:bogon(Ip)};
        false -> cached(Client, Ip)
    end.

chunk([], _Size) ->
    [];
chunk(List, Size) when length(List) =< Size ->
    [List];
chunk(List, Size) ->
    {Head, Tail} = lists:split(Size, List),
    [Head | chunk(Tail, Size)].

%% One POST /batch, mapped back onto the addresses it was asked about. A
%% chunk-level failure - the call refused, the transport failing, the retries
%% exhausted - becomes every address's error, exactly as it would have been had
%% each been looked up alone.
lookup_chunk(Client, Chunk, Options) ->
    Retries = maps:get(retries, Options, maps:get(retries, Client)),
    Body = iolist_to_binary(json:encode(#{<<"ips">> => Chunk})),
    case vpndetection_http:post_json(bound(Client, Options), <<"/batch">>, Body, Retries, chunk) of
        {ok, Answer} ->
            Results = object(maps:get(<<"results">>, Answer, #{})),
            Errors = object(maps:get(<<"errors">>, Answer, #{})),
            maps:from_list([{Ip, batch_answer(Ip, Results, Errors)} || Ip <- Chunk]);
        {error, Error} ->
            maps:from_list([{Ip, {error, Error}} || Ip <- Chunk])
    end.

object(Value) when is_map(Value) -> Value;
object(_) -> #{}.

%% Every address lands in exactly one of `results' and `errors'; an address in
%% neither is the server breaking its own contract, and is reported as such
%% rather than lost.
batch_answer(Ip, Results, Errors) ->
    case {Results, Errors} of
        {#{Ip := Served}, _} when is_map(Served) ->
            case vpndetection_http:conforms(lookup_shape(), Served) of
                ok -> {ok, vpndetection_result:from_wire(Served)};
                {error, Message} -> {error, #{kind => server_error, retryable => false, status => 200, message => Message}}
            end;
        {_, #{Ip := #{<<"status">> := Status, <<"error">> := Message}}}
          when is_integer(Status), is_binary(Message) ->
            {error, vpndetection_error:from_entry(Status, Message)};
        _ ->
            {error, #{kind => server_error, retryable => false, status => 200,
                      message => <<"the batch answer did not include ", Ip/binary>>}}
    end.

get_json(Client, Path, Query, Member) ->
    vpndetection_http:get_json(Client, Path, Query, maps:get(retries, Client), Member).

%% Each answer's shape, from the pinned spec's schemas: a member the spec
%% requires and never sends as null is required, a nullable or optional one may
%% be absent or null, and every one present has the spec's type. `standing',
%% `license_type', `format', `outcome', `confidence' and `tier' stay strings,
%% open sets as the spec documents them, and a sample row is an object whatever
%% its columns.
lookup_shape() ->
    Class = {object, [{<<"provider">>, string, false}, {<<"confidence">>, string, false},
                      {<<"last_seen">>, date, false}]},
    Proxy = {object, [{<<"provider">>, string, false}, {<<"first_seen">>, date, false},
                      {<<"last_seen">>, date, false}, {<<"hits">>, integer, false},
                      {<<"hits_days_pct">>, integer, false}, {<<"providers_num">>, integer, false}]},
    Flags = [{Flag, boolean, false} || Flag <- [<<"is_hosting">>, <<"is_relay">>, <<"is_tor">>, <<"is_cdn">>,
                                                <<"is_resproxy">>, <<"is_dcproxy">>, <<"is_mobproxy">>,
                                                <<"is_pubproxy">>]],
    {object, [{<<"ip">>, string, true}, {<<"is_vpn">>, boolean, true} | Flags] ++
             [{<<"vpn">>, {object, [{<<"provider">>, string, false}, {<<"last_seen">>, date, false},
                                     {<<"confidence">>, string, false}, {<<"method">>, string, false}]}, false},
              {<<"hosting">>, Class, false}, {<<"relay">>, Class, false}, {<<"tor">>, Class, false},
              {<<"cdn">>, Class, false}, {<<"resproxy">>, Proxy, false}, {<<"dcproxy">>, Proxy, false},
              {<<"mobproxy">>, Proxy, false},
              {<<"pubproxy">>, {object, [{<<"entry">>, boolean, false}, {<<"exit">>, boolean, false},
                                          {<<"protocols">>, {list, string}, false},
                                          {<<"num_ports">>, integer, false}, {<<"num_proxies">>, integer, false},
                                          {<<"last_seen">>, date, false}, {<<"last_usable">>, string, false}]},
               false},
              {<<"location">>, {object, [{Key, string, true} || Key <- [<<"continent">>, <<"continent_name">>,
                                                                     <<"country">>, <<"country_name">>,
                                                                     <<"timezone">>, <<"currency_code">>,
                                                                     <<"currency_name">>, <<"currency_symbol">>,
                                                                     <<"flag_emoji">>, <<"flag_unicode">>]]},
               false},
              {<<"asn">>, {object, [{<<"asn">>, integer, true}, {<<"name">>, string, true},
                                     {<<"domain">>, string, true}, {<<"type">>, string, true},
                                     {<<"prefix">>, string, true}]}, false}]}.

entitlement_shape() ->
    {object, [{<<"org_id">>, string, true},
              {<<"apikey">>, {object, [{<<"id">>, string, true}, {<<"expires">>, date_time, false},
                                        {<<"allowed_cidrs">>, {list, string}, true}]}, true},
              {<<"plan">>, {object, [{<<"key">>, string, true}, {<<"tier">>, string, true}]}, true},
              {<<"usage">>, {object, [{<<"requests">>, integer, true}, {<<"quota">>, integer, true},
                                       {<<"hard_limit">>, integer, false}, {<<"window_start">>, date_time, true},
                                       {<<"window_end">>, date_time, true}]}, true}]}.

database_shape() ->
    Format = {object, [{<<"format">>, string, true}, {<<"bytes">>, integer, false}]},
    Version = {object, [{<<"id">>, string, true}, {<<"version">>, integer, true}, {<<"summary">>, string, false},
                        {<<"formats">>, {list, Format}, true}, {<<"sample_formats">>, {list, string}, false}]},
    {object, [{<<"base">>, string, true}, {<<"name">>, string, true}, {<<"summary">>, string, true},
              {<<"license_type">>, string, false}, {<<"starts">>, date_time, false},
              {<<"expires">>, date_time, false}, {<<"renews_at">>, date_time, false},
              {<<"notice_due_at">>, date_time, false}, {<<"in_term">>, boolean, true},
              {<<"standing">>, string, true}, {<<"open">>, boolean, true},
              {<<"versions">>, {list, Version}, true}]}.

metadata_shape() ->
    Column = {object, [{<<"name">>, string, true}, {<<"type">>, string, true},
                       {<<"description">>, string, false}]},
    {object, [{<<"id">>, string, true}, {<<"update_freq">>, string, false}, {<<"updated">>, date, true},
              {<<"entries">>, integer, true}, {<<"schema">>, {map_of, {list, Column}}, true},
              {<<"sample">>, {map_of, {list, object}}, false}, {<<"size">>, {map_of, integer}, false},
              {<<"sample_size">>, {map_of, integer}, false}, {<<"sample_entries">>, integer, false}]}.

checksum_shape() ->
    {object, [{<<"id">>, string, true}, {<<"format">>, string, true},
              {<<"checksums">>, {object, [{<<"md5">>, string, true}, {<<"sha1">>, string, true},
                                           {<<"sha256">>, string, true}, {<<"sha512">>, string, true}]},
               true}]}.

download_shape() ->
    {object, [{<<"dataset_id">>, string, true}, {<<"format">>, string, true}, {<<"outcome">>, string, true},
              {<<"sample">>, boolean, true}, {<<"open">>, boolean, true}, {<<"bytes">>, integer, false},
              {<<"http_status">>, integer, false}, {<<"apikey_id">>, string, false},
              {<<"client_ip">>, string, false}, {<<"user_agent">>, string, false},
              {<<"created">>, date_time, true}]}.

%% The client with this call's `timeout_ms' in place of its own, which is the one
%% the transport reads for every request it builds.
bound(Client, Options) ->
    Client#{timeout_ms := maps:get(timeout_ms, Options, maps:get(timeout_ms, Client))}.

%% A call with a timeout no attempt can meet, or retries that are no count, is
%% refused before any request: httpc fails a call at once on zero, runs it with
%% no bound on a value it ignores, and raises in the caller past ?MAX_TIMEOUT_MS;
%% and Erlang orders every atom above every number, so `infinity' retries would
%% retry an outage for ever.
checked(Options, Call) ->
    case check_options(Options) of
        ok -> Call();
        {error, Error} -> {error, Error}
    end.

check_options(Options) ->
    TimeoutMs = maps:get(timeout_ms, Options, infinity),
    Retries = maps:get(retries, Options, 0),
    case {valid_timeout(TimeoutMs), valid_retries(Retries)} of
        {true, true} ->
            ok;
        {false, _} ->
            refused(io_lib:format("timeout_ms must be infinity or an integer from 1 to ~b, not ~p",
                                  [?MAX_TIMEOUT_MS, TimeoutMs]));
        {true, false} ->
            refused(io_lib:format("retries must be an integer of 0 or more, not ~p", [Retries]))
    end.

refused(Message) ->
    {error, #{kind => bad_request, retryable => false, message => iolist_to_binary(Message)}}.

valid_timeout(infinity) -> true;
valid_timeout(Ms) -> is_integer(Ms) andalso Ms >= 1 andalso Ms =< ?MAX_TIMEOUT_MS.

valid_retries(Retries) -> is_integer(Retries) andalso Retries >= 0.

%% Every one, not only the last: each path appended starts with its own `/', and
%% `//api/...' is another path, one the API answers with a redirect.
trim_slashes(<<>>) ->
    <<>>;
trim_slashes(Url) ->
    case binary:last(Url) of
        $/ -> trim_slashes(binary:part(Url, 0, byte_size(Url) - 1));
        _ -> Url
    end.

%% An unpublished format is refused here rather than sent, where it would cost a
%% round trip and come back a 400 naming nothing the caller can act on.
format_name(Format) ->
    case lists:member(Format, ?FORMATS) of
        true ->
            {ok, atom_to_binary(Format)};
        false ->
            Message = io_lib:format("~p is not a published format; expected one of ~p",
                                    [Format, ?FORMATS]),
            {error, #{kind => bad_request, retryable => false,
                      message => iolist_to_binary(Message)}}
    end.

cache(false) ->
    undefined;
cache(Options) ->
    {ok, Cache} = vpndetection_cache:start_link(maps:get(max, Options, ?DEFAULT_CACHE_MAX),
                                                maps:get(ttl_ms, Options, ?DEFAULT_CACHE_TTL_MS)),
    Cache.

%% Blank counts as absent: it is what an unset `${{ secrets.X }}' interpolates
%% to, as `false' is what `os:getenv/1' answers for an unset variable, and sent,
%% `Bearer' with nothing after it reads as a wrong key rather than as none. httpc
%% writes a header value out as given, so a control character left inside would
%% reach the wire with every call, and a CR LF would start a header of its own. A
%% key read from a file ends with a newline, which the trim takes.
api_key(Key) when Key =:= undefined; Key =:= false; Key =:= nil ->
    undefined;
api_key(Key) ->
    Trimmed = trim_blank(bin(Key)),
    case {Trimmed, lists:any(fun(C) -> C < 32 orelse C =:= 127 end, binary_to_list(Trimmed))} of
        {<<>>, _} -> undefined;
        {_, false} -> Trimmed;
        {_, true} -> erlang:error({badarg, {api_key, control_character}})
    end.

trim_blank(<<C, Rest/binary>>) when C =:= $\s; C >= $\t, C =< $\r ->
    trim_blank(Rest);
trim_blank(Value) ->
    Size = byte_size(Value),
    case Size > 0 andalso binary:last(Value) of
        C when C =:= $\s; C >= $\t, C =< $\r -> trim_blank(binary:part(Value, 0, Size - 1));
        _ -> Value
    end.

%% Loaded first: a library is seldom started, and an application that is not
%% loaded has no `vsn' to read.
user_agent() ->
    _ = application:load(vpndetection),
    Version = case application:get_key(vpndetection, vsn) of
        {ok, Vsn} -> list_to_binary(Vsn);
        undefined -> <<"dev">>
    end,
    <<"vpndetection-erlang/", Version/binary>>.

bin(Value) when is_binary(Value) -> Value;
bin(Value) when is_list(Value) -> list_to_binary(Value).

%% A tuple that is no address raises `badarg' naming it, as a malformed option
%% does in `new/1'.
address(Ip) when is_tuple(Ip) ->
    case inet:ntoa(Ip) of
        {error, einval} -> erlang:error({badarg, {ip, Ip}});
        Text -> list_to_binary(Text)
    end;
address(Ip) ->
    bin(Ip).
