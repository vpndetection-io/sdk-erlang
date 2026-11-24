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
    api_key => binary() | string() | false | nil,
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
    %% Send the request's own User-Agent with its lookup, and never refuse a
    %% request whose answer's `user_agent' verdict is `verified', whatever the
    %% condition matches; the answer is still attached. An absent or empty header
    %% sends none. Off by default, so the cache holds one answer per address
    %% rather than one per agent.
    allow_bots => boolean(),
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
    allow_bots := boolean(),
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
            OnWarn = maps:get(on_warn, Options, fun(M) -> logger:warning(M) end),
            unset_key(Options, OnWarn),
            {ok, #{
                client => Client,
                owns_client => Owns,
                selector => maps:get(
                    ip_selector, Options, vpndetection_selectors:framework_ip()
                ),
                condition => Condition,
                fail_closed => maps:get(fail_closed, Options, false),
                allow_bots => maps:get(allow_bots, Options, false) =:= true,
                on_missing_field => maps:get(on_missing_field, Options, warn),
                on_warn => OnWarn,
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
%% naming a member the plan does not serve, or `allow_bots' sending an agent
%% that is answered no verdict, with `on_missing_field' set to `error'.
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
            classify(Core, Ip, agent(Core, View))
    end.

%% The request's own User-Agent, sent only with `allow_bots' on; an absent or
%% empty header sends none.
agent(#{allow_bots := true}, View) ->
    case (maps:get(header, View))(<<"user-agent">>) of
        undefined -> undefined;
        Value -> empty_to_undefined(string:trim(iolist_to_binary(Value)))
    end;
agent(_Core, _View) ->
    undefined.

address(Core, View) ->
    case vpndetection_selectors:resolve(maps:get(selector, Core), View) of
        undefined -> undefined;
        Value -> empty_to_undefined(string:trim(iolist_to_binary(Value)))
    end.

empty_to_undefined(<<>>) -> undefined;
empty_to_undefined(Ip) -> Ip.

classify(Core, Ip, Agent) ->
    maybe_warn_bogon(Core, Ip),
    maybe_warn_dead_cache(Core),
    Options = case Agent of
        undefined -> #{};
        _ -> #{user_agent => Agent}
    end,
    case vpndetection:lookup(maps:get(client, Core), Ip, Options) of
        {error, Error} ->
            {ok, #{
                blocked => maps:get(fail_closed, Core),
                ip => Ip,
                result => undefined,
                error => Error
            }};
        {ok, Result} ->
            case report_verdict(Core, Agent, Result) of
                {error, _} = Error -> Error;
                ok -> decide(Core, Ip, Result)
            end
    end.

decide(#{condition := undefined}, Ip, Result) ->
    {ok, #{blocked => false, ip => Ip, result => Result, error => undefined}};
decide(Core, Ip, Result) ->
    Condition = maps:get(condition, Core),
    case report_missing(Core, Condition, Result) of
        {error, _} = Error ->
            Error;
        ok ->
            Blocked = not verified(Core, Result) andalso vpndetection_condition:matches(Condition, Result),
            {ok, #{blocked => Blocked, ip => Ip, result => Result, error => undefined}}
    end.

%% A crawler its operator vouches for, which `allow_bots' never refuses.
verified(#{allow_bots := true}, #{user_agent := #{verdict := <<"verified">>}}) -> true;
verified(_Core, _Result) -> false.

%% An agent was sent and a served answer carries no verdict: a keyless client, or
%% a free key past its trial, is never answered one, so nothing is let through.
%% A bogon is answered locally, with none.
report_verdict(_Core, undefined, _Result) ->
    ok;
report_verdict(_Core, _Agent, #{user_agent := _}) ->
    ok;
report_verdict(_Core, _Agent, #{is_bogon := true}) ->
    ok;
report_verdict(Core, _Agent, _Result) ->
    report(Core, [<<"user_agent">>],
           <<"allow_bots sent the request's user agent, and the answer carries no user_agent verdict, "
             "so no crawler is let through: a keyless client, or a free key past its trial, is never "
             "answered one">>).

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
            report(Core, Missing, Message)
    end.

%% What the plan does not serve, said as `on_missing_field' asks: an error, a
%% warning once, or nothing.
report(#{on_missing_field := ignore}, _Missing, _Message) ->
    ok;
report(#{on_missing_field := error}, Missing, Message) ->
    {error, {missing_members, Missing, Message}};
report(Core, _Missing, Message) ->
    warn(Core, Message).

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
                "load balancer, pass an ip_selector that reads the address your edge forwards: "
                "the socket peer is the proxy's own."
            >>)
    end.

%% A cache whose process has exited answers every read as a miss, so each request
%% costs a lookup and nothing else says so: a core built in an application's
%% `start/2' links its cache to the application master, which ignores the exit.
maybe_warn_dead_cache(#{client := #{cache := #{pid := _} = Cache}} = Core) ->
    case vpndetection_cache:alive(Cache) of
        true ->
            ok;
        false ->
            warn(Core, <<
                "the result cache has stopped, so every request now costs a lookup. Build the "
                "core again to restore it, in a process that outlives it"
            >>)
    end;
maybe_warn_dead_cache(_Core) ->
    ok.

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

%% `false' is what `os:getenv/1' answers for a variable that is not set, so a core
%% built from one runs with no key: said once, here, because every lookup then
%% answers none of the flags a key adds.
unset_key(#{client := _}, _OnWarn) ->
    ok;
unset_key(#{api_key := false}, OnWarn) ->
    _ = OnWarn(<<"api_key is false, which os:getenv/1 answers for an unset variable, so every lookup "
                 "goes out with no key, without the hosting, CDN and proxy flags">>),
    ok;
unset_key(#{api_key := nil}, OnWarn) ->
    _ = OnWarn(<<"api_key is nil, which Elixir's System.get_env/1 answers for an unset variable, so "
                 "every lookup goes out with no key, without the hosting, CDN and proxy flags">>),
    ok;
unset_key(_Options, _OnWarn) ->
    ok.

client(#{client := Client}) ->
    {Client, false};
client(Options) ->
    Base = #{
        timeout_ms => maps:get(timeout_ms, Options, ?DEFAULT_TIMEOUT_MS),
        retries => maps:get(retries, Options, ?DEFAULT_RETRIES)
    },
    Carried = maps:with([api_key, base_url], Options),
    {vpndetection:new(maps:merge(Base, Carried)), true}.
