%% @doc The framework-agnostic half of a web middleware: resolve a client
%% address, classify it, and decide whether the condition matched.
%%
%% An adapter - `vpndetection_cowboy' is the one we publish - keeps only the
%% parts that are genuinely framework-shaped and shares everything here, so the
%% shared conformance corpus is asserted once for Erlang rather than once per
%% framework.
%%
%% Blocking is opt-in. Without a `block_condition' this only enriches: every
%% request carries a `lookup()' and what it means is the application's decision.
-module(vpndetection_middleware).

-export([new/1, evaluate/2, blocking/1, close/1]).

-export_type([core/0, options/0, lookup/0]).

%% Defaults set for a request path rather than for a script: failing open
%% quickly beats holding a visitor while we try again.
-define(DEFAULT_TIMEOUT_MS, 2500).
-define(DEFAULT_RETRIES, 0).

-type options() :: #{
    %% An existing client to use. Prefer this if you already hold one: two
    %% clients mean two caches, and a cache is per instance because two keys can
    %% be on different plans and entitled to different fields. A client passed
    %% in is NOT closed by close/1.
    client => vpndetection:client(),
    api_key => binary() | string(),
    base_url => binary() | string(),
    %% How long a lookup may hold the request. Ignored when `client' is set.
    timeout_ms => pos_integer(),
    %% Retry attempts for a transient failure. Ignored when `client' is set.
    retries => non_neg_integer(),
    %% How the client address is decided. Defaults to the framework's own accessor.
    ip_selector => vpndetection_selectors:selector(),
    %% What to block on. Leave it out to only enrich the request.
    block_condition => vpndetection_condition:conditions(),
    %% Block when the lookup itself fails. Our outage should not become yours.
    fail_closed => boolean(),
    on_missing_field => warn | error | ignore,
    %% Where warnings go. Defaults to logger:warning/1.
    on_warn => fun((binary()) -> any())
}.

%% What a middleware attached to the request, whether or not it succeeded.
-type lookup() :: #{
    %% Whether the condition matched. Always false when none was configured.
    blocked := boolean(),
    %% The address that was classified, as the selector resolved it.
    ip := binary() | undefined,
    %% The answer, or `undefined' when the lookup failed.
    result := vpndetection_result:result() | undefined,
    %% Why the lookup failed, or `undefined' when it succeeded.
    error := vpndetection_error:error() | undefined
}.

-opaque core() :: #{
    client := vpndetection:client(),
    owns_client := boolean(),
    selector := vpndetection_selectors:selector(),
    condition := vpndetection_condition:conditions() | undefined,
    fail_closed := boolean(),
    on_missing_field := warn | error | ignore,
    on_warn := fun((binary()) -> any()),
    warned := reference()
}.

%% @doc Build a core, refusing a condition that constrains nothing.
-spec new(options()) -> {ok, core()} | {error, term()}.
new(Options) ->
    Condition = maps:get(block_condition, Options, undefined),
    case vpndetection_condition:validate(Condition) of
        {error, {constrains_nothing, One}} ->
            {error,
                {constrains_nothing, One,
                    <<"a block condition that constrains nothing would block every request; "
                        "a member set to false or null is ignored, so state the positive "
                        "signals you act on">>}};
        ok ->
            {Client, Owns} = client(Options),
            {ok, #{
                client => Client,
                owns_client => Owns,
                selector => maps:get(
                    ip_selector, Options, vpndetection_selectors:framework_ip()
                ),
                condition => Condition,
                fail_closed => maps:get(fail_closed, Options, false),
                on_missing_field => maps:get(on_missing_field, Options, warn),
                on_warn => maps:get(on_warn, Options, fun(M) -> logger:warning(M) end),
                warned => make_ref()
            }}
    end.

%% @doc Whether a condition was configured at all.
-spec blocking(core()) -> boolean().
blocking(#{condition := undefined}) -> false;
blocking(_Core) -> true.

%% @doc Release the client this core built. A client PASSED IN stays open,
%% because its owner is whoever passed it.
-spec close(core()) -> ok.
close(#{owns_client := true, client := Client}) -> vpndetection:close(Client);
close(_Core) -> ok.

%% @doc Classify one request.
%%
%% A failed LOOKUP is not an error here: it lands on the `error' key and the
%% request is let through. What CAN fail is a misconfiguration - a condition
%% naming a member the plan does not serve, with `on_missing_field' set to
%% `error'.
-spec evaluate(core(), vpndetection_selectors:view()) ->
    {ok, lookup()} | {error, {missing_members, [binary()], binary()}}.
evaluate(Core, View) ->
    case address(Core, View) of
        undefined ->
            warn(
                Core,
                <<"could not resolve a client address from this request; pass an ip_selector "
                    "that knows where yours comes from">>
            ),
            {ok, #{
                blocked => maps:get(fail_closed, Core),
                ip => undefined,
                result => undefined,
                error => #{
                    kind => bad_request,
                    message => <<"no client address on the request">>,
                    retryable => false
                }
            }};
        Ip ->
            classify(Core, Ip)
    end.

address(Core, View) ->
    case vpndetection_selectors:resolve(maps:get(selector, Core), View) of
        undefined -> undefined;
        Value -> empty_to_undefined(string:trim(iolist_to_binary(Value)))
    end.

empty_to_undefined(<<>>) -> undefined;
empty_to_undefined(Ip) -> Ip.

classify(Core, Ip) ->
    maybe_warn_bogon(Core, Ip),
    case vpndetection:lookup(maps:get(client, Core), Ip) of
        {error, Error} ->
            {ok, #{
                blocked => maps:get(fail_closed, Core),
                ip => Ip,
                result => undefined,
                error => Error
            }};
        {ok, Result} ->
            decide(Core, Ip, Result)
    end.

decide(#{condition := undefined}, Ip, Result) ->
    {ok, #{blocked => false, ip => Ip, result => Result, error => undefined}};
decide(Core, Ip, Result) ->
    Condition = maps:get(condition, Core),
    case report_missing(Core, Condition, Result) of
        {error, _} = Error ->
            Error;
        ok ->
            Blocked = vpndetection_condition:matches(Condition, Result),
            {ok, #{blocked => Blocked, ip => Ip, result => Result, error => undefined}}
    end.

report_missing(#{on_missing_field := ignore}, _Condition, _Result) ->
    ok;
report_missing(Core, Condition, Result) ->
    case vpndetection_condition:missing_members(Condition, Result) of
        [] ->
            ok;
        Missing ->
            Message = iolist_to_binary([
                "block_condition names ",
                lists:join(", ", Missing),
                ", which your plan does not include, so those terms can never match. "
                "An absent member means \"not in your plan\", not \"checked, and no\"."
            ]),
            case maps:get(on_missing_field, Core) of
                error -> {error, {missing_members, Missing, Message}};
                warn -> warn(Core, Message)
            end
    end.

%% Expected in local development. Anywhere else it means a proxy sits in front
%% and its own address is what reached us.
maybe_warn_bogon(Core, Ip) ->
    case vpndetection_bogon:is_bogon(Ip) of
        false ->
            ok;
        true ->
            warn(Core, <<
                "resolved the client address as ",
                Ip/binary,
                ", which is not a public address. If this application runs behind a proxy or "
                "load balancer, configure its trusted-proxy setting or pass an ip_selector "
                "that reads your edge's header."
            >>)
    end.

%% A misconfiguration is the same on every request, so saying so once is a
%% warning and saying so a million times is an outage of its own.
%%
%% The seen-set is in `persistent_term' keyed by the core's own reference: this
%% module hands out a plain map with no process behind it, and a term written
%% once and then only read is exactly what persistent_term is for. An ets table
%% would need an owner to outlive every request, which a map cannot promise.
warn(Core, Message) ->
    Key = {?MODULE, maps:get(warned, Core), erlang:phash2(Message)},
    case persistent_term:get(Key, false) of
        true ->
            ok;
        false ->
            persistent_term:put(Key, true),
            _ = (maps:get(on_warn, Core))(Message),
            ok
    end.

client(#{client := Client}) ->
    {Client, false};
client(Options) ->
    Base = #{
        timeout_ms => maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
        retries => maps:get(retries, Options, ?DEFAULT_RETRIES)
    },
    Carried = maps:with([api_key, base_url], Options),
    {vpndetection:new(maps:merge(Base, Carried)), true}.
