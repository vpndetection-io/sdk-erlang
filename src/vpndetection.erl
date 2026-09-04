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
-export([database_list/1, database_metadata/2, database_checksums/3,
         database_downloads/1, database_download_url/3, database_download/4,
         database_download_bytes/3]).

-export_type([client/0, options/0, lookup_options/0, batch_options/0, format/0]).

-define(DEFAULT_BASE_URL, <<"https://api.vpndetection.io">>).
-define(DEFAULT_CONCURRENCY, 8).
-define(DEFAULT_RETRIES, 2).
-define(DEFAULT_CACHE_MAX, 10000).
-define(DEFAULT_CACHE_TTL_MS, 3600000).
-define(DEFAULT_TIMEOUT_MS, 30000).
-define(BATCH_TAG, '$vpndetection_batch').

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

-type lookup_options() :: #{retries => non_neg_integer()}.
-type batch_options() :: #{retries => non_neg_integer(), concurrency => pos_integer()}.
-type format() :: csvgz | mmdb.

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
-spec lookup(client(), binary() | string(), lookup_options()) ->
    {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
lookup(Client, Ip, Options) ->
    Addr = bin(Ip),
    case vpndetection_bogon:is_bogon(Addr) of
        true -> {ok, vpndetection_result:bogon(Addr)};
        false -> served(Client, Addr, Options)
    end.

-spec lookup_batch(client(), [binary() | string()]) ->
    #{binary() => {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}}.
lookup_batch(Client, Ips) ->
    lookup_batch(Client, Ips, #{}).

%% @doc Classify many addresses at once, one process per address up to the
%% concurrency bound.
%%
%% Keyed by address rather than positional, so duplicates in the input collapse
%% to a single request and the caller never has to line two lists up. An address
%% that fails carries its `{error, Error}' as its value, so one bad entry cannot
%% lose the rest of the answers. Erlang maps have no insertion order, so the
%% result is a set of keys rather than a sequence.
%%
%% `concurrency' and `retries' are overridable here, per call, so one large batch
%% does not need a second client built to widen it.
-spec lookup_batch(client(), [binary() | string()], batch_options()) ->
    #{binary() => {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}}.
lookup_batch(Client, Ips, Options) ->
    Unique = lists:uniq([bin(Ip) || Ip <- Ips]),
    Concurrency = maps:get(concurrency, Options, maps:get(concurrency, Client)),
    dispatch(fun(Ip) -> lookup(Client, Ip, Options) end, Unique, Concurrency, #{}, #{}, #{}).

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
    unwrap(get_json(Client, <<"/api/v1/database/list">>, []), <<"datasets">>).

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
    Query = [{<<"id">>, bin(Id)}, {<<"format">>, atom_to_binary(Format)}],
    unwrap(get_json(Client, <<"/api/v1/database/checksum">>, Query), <<"checksums">>).

%% @doc Your organization's recent download attempts, newest first.
-spec database_downloads(client()) -> {ok, [map()]} | {error, vpndetection_error:error()}.
database_downloads(Client) ->
    unwrap(get_json(Client, <<"/api/v1/database/downloads">>, []), <<"downloads">>).

%% @doc The time-limited URL for one dataset file.
%%
%% The URL is returned rather than the bytes, so the caller decides how to
%% transfer a file that routinely runs to gigabytes. The link authorizes the
%% START of a transfer, so one already running is not interrupted when it lapses.
-spec database_download_url(client(), binary() | string(), format()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
database_download_url(Client, Id, Format) ->
    Query = [{<<"id">>, bin(Id)}, {<<"format">>, atom_to_binary(Format)}],
    vpndetection_http:get_redirect(Client, <<"/api/v1/database/download">>, Query,
                                   maps:get(retries, Client)).

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
            case vpndetection_http:get_json(Client, Path, [], Retries) of
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

get_json(Client, Path, Query) ->
    vpndetection_http:get_json(Client, Path, Query, maps:get(retries, Client)).

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
