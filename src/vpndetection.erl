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

-export_type([client/0, options/0, lookup_options/0, batch_options/0, downloads_options/0,
              format/0]).
-export_type([oauth_options/0, device_authorization_options/0]).

-define(DEFAULT_BASE_URL, <<"https://api.vpndetection.io">>).
-define(DEFAULT_CONCURRENCY, 8).
-define(DEFAULT_RETRIES, 2).
-define(DEFAULT_CACHE_MAX, 10000).
-define(DEFAULT_CACHE_TTL_MS, 3600000).
-define(DEFAULT_TIMEOUT_MS, 30000).
-define(BATCH_TAG, '$vpndetection_batch').
%% The most addresses POST /batch takes in one call; a larger batch is sent in
%% chunks of this size.
-define(BATCH_MAX, 1000).

-opaque client() :: #{
    base_url := binary(),
    api_key := binary() | undefined,
    cache := vpndetection_cache:cache() | undefined,
    concurrency := pos_integer(),
    retries := non_neg_integer(),
    timeout_ms := pos_integer(),
    user_agent := binary(),
    http := vpndetection_http:http_fun()
}.

-type options() :: #{
    api_key => binary() | string(),
    base_url => binary() | string(),
    cache => #{max => pos_integer(), ttl_ms => pos_integer()} | false,
    concurrency => pos_integer(),
    retries => non_neg_integer(),
    timeout_ms => pos_integer(),
    http => vpndetection_http:http_fun()
}.

-type lookup_options() :: #{retries => non_neg_integer(), timeout_ms => pos_integer()}.
-type batch_options() :: #{retries => non_neg_integer(), concurrency => pos_integer(),
                           timeout_ms => pos_integer()}.
-type downloads_options() :: #{limit => pos_integer(), timeout_ms => pos_integer()}.
-type format() :: csvgz | mmdb.
%% The same set at runtime, because `format()' checks nothing once compiled.
-define(FORMATS, [csvgz, mmdb]).

-type oauth_options() :: #{timeout_ms => pos_integer()}.
-type device_authorization_options() :: #{scope => binary() | string(),
                                          resource => binary() | string(),
                                          timeout_ms => pos_integer()}.

-spec new() -> client().
new() ->
    new(#{}).

%% @doc Build a client.
%%
%% `api_key' is optional: without one you get the free tier, which answers `ip'
%% and `is_vpn' and allows 1000 requests per day per source address.
%%
%% The cache is per client and never shared, because two clients holding
%% different keys are on different plans and so entitled to different fields.
%% Unless `cache' is `false' this starts a process linked to the caller, so build
%% clients somewhere long lived and `close/1' them when you are done.
-spec new(options()) -> client().
new(Options) ->
    case maps:is_key(http, Options) of
        false -> vpndetection_http:ensure_ready();
        true -> ok
    end,
    #{
        base_url => bin(maps:get(base_url, Options, ?DEFAULT_BASE_URL)),
        api_key => api_key(Options),
        cache => cache(maps:get(cache, Options, #{})),
        concurrency => maps:get(concurrency, Options, ?DEFAULT_CONCURRENCY),
        retries => maps:get(retries, Options, ?DEFAULT_RETRIES),
        timeout_ms => maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
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

-spec lookup(client(), binary() | string()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
lookup(Client, Ip) ->
    lookup(Client, Ip, #{}).

%% @doc Classify one address.
%%
%% A bogon is answered locally and never reaches the network. Everything else is
%% served, then cached for this client alone.
%%
%% `Options' overrides the client's `retries' and `timeout_ms' for this call
%% alone. `timeout_ms' bounds each attempt, so a retried call can take longer in
%% total.
-spec lookup(client(), binary() | string(), lookup_options()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
lookup(Client, Ip, Options) ->
    Addr = bin(Ip),
    case vpndetection_bogon:is_bogon(Addr) of
        true -> {ok, vpndetection_result:bogon(Addr)};
        false -> served(Client, Addr, Options)
    end.

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
    Retries = maps:get(retries, Options, maps:get(retries, Client)),
    case vpndetection_http:get_json(bound(Client, Options), <<"/myip">>, [], Retries) of
        {ok, Body} -> {ok, vpndetection_result:from_wire(Body)};
        {error, Error} -> {error, Error}
    end.

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
    Retries = maps:get(retries, Options, maps:get(retries, Client)),
    vpndetection_http:get_json(bound(Client, Options), <<"/api/v1/entitlement">>, [], Retries).

-spec lookup_batch(client(), [binary() | string()]) ->
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
%% than a sequence.
%%
%% `concurrency', `retries' and `timeout_ms' are overridable here, per call, so
%% one large batch does not need a second client built to widen it. There is no
%% cap on how many addresses one call takes; chunking them is this function's job.
-spec lookup_batch(client(), [binary() | string()], batch_options()) ->
    #{binary() => {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}}.
lookup_batch(Client, Ips, Options) ->
    Unique = lists:uniq([bin(Ip) || Ip <- Ips]),
    case maps:get(concurrency, Options, maps:get(concurrency, Client)) of
        Concurrency when is_integer(Concurrency), Concurrency >= 1 ->
            batch(Client, Unique, Options, Concurrency);
        %% A dispatcher that may run nothing waits for ever, so this is the
        %% caller's mistake to hear about at once.
        Refused ->
            Message = iolist_to_binary(io_lib:format("concurrency must be at least 1, not ~p", [Refused])),
            Error = #{kind => bad_request, retryable => false, message => Message},
            maps:from_list([{Ip, {error, Error}} || Ip <- Unique])
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
%% A licence covers a family (`vpn_ip'), while a download names one of its
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
    unwrap(get_json(Client, <<"/api/v1/database/list">>, []), <<"databases">>).

%% @doc What is inside one dataset: schema, samples, row count, sizes.
-spec database_metadata(client(), binary() | string()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
database_metadata(Client, Id) ->
    get_json(Client, <<"/api/v1/database/metadata">>, [{<<"id">>, bin(Id)}]).

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
            unwrap(get_json(Client, <<"/api/v1/database/checksum">>, Query), <<"checksums">>);
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
    unwrap(get_json(bound(Client, Options), <<"/api/v1/database/downloads">>, Query),
           <<"downloads">>).

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
    vpndetection_oauth:metadata(Client, Options).

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
    vpndetection_oauth:device_authorization(Client, bin(ClientId), Extra, Options).

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
    vpndetection_oauth:exchange_device_code(Client, bin(ClientId), bin(DeviceCode), Options).

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
    vpndetection_oauth:exchange_refresh_token(Client, bin(ClientId), bin(RefreshToken), Options).

-spec oauth_revoke(client(), binary() | string(), binary() | string()) ->
    ok | {error, vpndetection_error:error()}.
oauth_revoke(Client, ClientId, Token) ->
    oauth_revoke(Client, ClientId, Token, #{}).

%% @doc Revoke an access or a refresh token. A refresh token ends the whole grant
%% and every token it issued, which is how a machine signs out.
-spec oauth_revoke(client(), binary() | string(), binary() | string(), oauth_options()) ->
    ok | {error, vpndetection_error:error()}.
oauth_revoke(Client, ClientId, Token, Options) ->
    vpndetection_oauth:revoke(Client, bin(ClientId), bin(Token), Options).

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
    vpndetection_oauth:poll_device_token(Client, bin(ClientId), Device, Options).

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

served(Client, Addr, Options) ->
    case cached(Client, Addr) of
        {ok, Result} ->
            {ok, Result};
        miss ->
            Path = <<"/", (vpndetection_http:escape(Addr))/binary>>,
            Retries = maps:get(retries, Options, maps:get(retries, Client)),
            case vpndetection_http:get_json(bound(Client, Options), Path, [], Retries) of
                {ok, Body} -> store(Client, Addr, vpndetection_result:from_wire(Body));
                {error, Error} -> {error, Error}
            end
    end.

cached(#{cache := undefined}, _Addr) ->
    miss;
cached(#{cache := Cache}, Addr) ->
    vpndetection_cache:get(Cache, Addr).

%% Errors are never cached: a 500 or a rate limit says nothing about the address.
store(#{cache := undefined}, _Addr, Result) ->
    {ok, Result};
store(#{cache := Cache}, Addr, Result) ->
    vpndetection_cache:put(Cache, Addr, Result),
    {ok, Result}.

batch(Client, Unique, Options, Concurrency) ->
    {Answered, Pending} = lists:foldl(fun(Ip, {Acc, Rest}) ->
        case local(Client, Ip) of
            {ok, Result} -> {Acc#{Ip => {ok, Result}}, Rest};
            miss -> {Acc, [Ip | Rest]}
        end
    end, {#{}, []}, Unique),
    Chunks = chunk(lists:reverse(Pending), ?BATCH_MAX),
    ByChunk = dispatch(fun(Chunk) -> lookup_chunk(Client, Chunk, Options) end,
                       Chunks, Concurrency, #{}, #{}, #{}),
    maps:fold(fun
        (_Chunk, Answers, Acc) when is_map(Answers) -> maps:merge(Acc, Answers);
        (Chunk, Error, Acc) -> maps:merge(Acc, maps:from_list([{Ip, Error} || Ip <- Chunk]))
    end, Answered, ByChunk).

%% Bounded fan-out. At most `Limit' workers are alive at any moment, so the
%% concurrency setting is the number of requests actually in flight rather than
%% a hint. spawn_monitor rather than spawn, rather than waiting on results alone,
%% so a worker that dies without answering cannot hang the batch.
dispatch(Fun, [Item | Rest], Limit, Pending, Done, Acc) when map_size(Pending) < Limit ->
    Parent = self(),
    {Pid, _Mon} = spawn_monitor(fun() -> Parent ! {?BATCH_TAG, self(), Fun(Item)} end),
    dispatch(Fun, Rest, Limit, Pending#{Pid => Item}, Done, Acc);
dispatch(_Fun, [], _Limit, Pending, _Done, Acc) when map_size(Pending) =:= 0 ->
    Acc;
dispatch(Fun, Queue, Limit, Pending, Done, Acc) ->
    receive
        {?BATCH_TAG, Pid, Result} ->
            dispatch(Fun, Queue, Limit, Pending, Done#{Pid => Result}, Acc);
        {'DOWN', _Mon, process, Pid, Reason} ->
            %% Signals between a pair of processes keep their order, so a result
            %% sent before the worker exited is already in Done by now.
            Item = maps:get(Pid, Pending),
            Result = maps:get(Pid, Done, {error, worker_died(Reason)}),
            dispatch(Fun, Queue, Limit, maps:remove(Pid, Pending), maps:remove(Pid, Done),
                     Acc#{Item => Result})
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
    case vpndetection_http:post_json(bound(Client, Options), <<"/batch">>, Body, Retries) of
        {ok, Answer} ->
            Results = object(maps:get(<<"results">>, Answer, #{})),
            Errors = object(maps:get(<<"errors">>, Answer, #{})),
            maps:from_list([{Ip, batch_answer(Client, Ip, Results, Errors)} || Ip <- Chunk]);
        {error, Error} ->
            maps:from_list([{Ip, {error, Error}} || Ip <- Chunk])
    end.

object(Value) when is_map(Value) -> Value;
object(_) -> #{}.

%% Every address lands in exactly one of `results' and `errors'; an address in
%% neither is the server breaking its own contract, and is reported as such
%% rather than lost.
batch_answer(Client, Ip, Results, Errors) ->
    case {Results, Errors} of
        {#{Ip := Served}, _} when is_map(Served) ->
            store(Client, Ip, vpndetection_result:from_wire(Served));
        {_, #{Ip := #{<<"status">> := Status, <<"error">> := Message}}}
          when is_integer(Status), is_binary(Message) ->
            {error, vpndetection_error:from_entry(Status, Message)};
        _ ->
            {error, #{kind => server_error, retryable => false, status => 200,
                      message => <<"the batch answer did not include ", Ip/binary>>}}
    end.

get_json(Client, Path, Query) ->
    vpndetection_http:get_json(Client, Path, Query, maps:get(retries, Client)).

%% The client with this call's `timeout_ms' in place of its own, which is the one
%% the transport reads for every request it builds.
bound(Client, Options) ->
    Client#{timeout_ms := maps:get(timeout_ms, Options, maps:get(timeout_ms, Client))}.

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

unwrap({ok, Body}, Key) ->
    case Body of
        #{Key := Value} -> {ok, Value};
        _ -> {error, #{kind => server_error, retryable => false,
                       message => <<"response did not carry a \"", Key/binary, "\" member">>}}
    end;
unwrap({error, Error}, _Key) ->
    {error, Error}.

cache(false) ->
    undefined;
cache(Options) ->
    {ok, Cache} = vpndetection_cache:start_link(maps:get(max, Options, ?DEFAULT_CACHE_MAX),
                                                maps:get(ttl_ms, Options, ?DEFAULT_CACHE_TTL_MS)),
    Cache.

api_key(Options) ->
    case maps:get(api_key, Options, undefined) of
        undefined -> undefined;
        Key -> bin(Key)
    end.

user_agent() ->
    Version = case application:get_key(vpndetection, vsn) of
        {ok, Vsn} -> list_to_binary(Vsn);
        undefined -> <<"dev">>
    end,
    <<"vpndetection-erlang/", Version/binary>>.

bin(Value) when is_binary(Value) -> Value;
bin(Value) when is_list(Value) -> list_to_binary(Value).
