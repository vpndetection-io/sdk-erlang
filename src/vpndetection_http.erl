%% @doc The transport: one httpc profile, retry policy, and response classification.
-module(vpndetection_http).

-export([ensure_ready/0, httpc_fun/0, get_json/4, get_redirect/4, escape/1]).

-export_type([request/0, response/0, http_fun/0]).

-type request() :: #{
    method := get,
    url := binary(),
    headers := [{binary(), binary()}],
    timeout_ms := pos_integer()
}.

-type response() :: {ok, #{status := 100..599, headers := [{binary(), binary()}], body := binary()}}
                  | {error, term()}.

-type http_fun() :: fun((request()) -> response()).

%% Requests go through a profile of our own rather than httpc's default one, so
%% an application that retunes the default profile (a proxy, a different
%% ipfamily, its own timeouts) does not silently reconfigure this client, and
%% this client cannot reconfigure theirs. httpc options are per profile.
%%
%% The profile is deliberately left at httpc's own defaults. Its `max_sessions'
%% of 2 does NOT throttle a batch: measured against a local origin, 32 requests
%% at a concurrency of 16 peaked at 16 in flight and reused 16 connections,
%% identically at `max_sessions' 2 and 16. The bound that matters is the one the
%% batch dispatcher applies.
-define(PROFILE, vpndetection_httpc).
-define(BACKOFF_BASE_MS, 200).
-define(BACKOFF_CAP_MS, 5000).

%% @doc Start what the default transport needs.
-spec ensure_ready() -> ok.
ensure_ready() ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    case inets:start(httpc, [{profile, ?PROFILE}]) of
        {ok, _} -> ok;
        {error, {already_started, _}} -> ok
    end.

%% @doc The default transport, closing over nothing.
-spec httpc_fun() -> http_fun().
httpc_fun() ->
    fun(#{method := get, url := Url, headers := Headers, timeout_ms := TimeoutMs}) ->
        Request = {binary_to_list(Url), [{binary_to_list(K), binary_to_list(V)} || {K, V} <- Headers]},
        %% autoredirect MUST stay false. The download endpoint answers 302 to
        %% object storage, and following it would pull a dataset that routinely
        %% runs to gigabytes into memory as one binary.
        HttpOpts = [{timeout, TimeoutMs}, {connect_timeout, TimeoutMs}, {autoredirect, false}],
        case httpc:request(get, Request, HttpOpts, [{body_format, binary}], ?PROFILE) of
            {ok, {{_Version, Status, _Phrase}, RespHeaders, Body}} ->
                {ok, #{status => Status, headers => normalize(RespHeaders), body => Body}};
            {error, Reason} ->
                {error, Reason}
        end
    end.

%% @doc Fetch and decode a JSON body, retrying what is worth retrying.
-spec get_json(map(), binary(), [{binary(), binary()}], non_neg_integer()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
get_json(Client, Path, Query, Retries) ->
    with_retry(Client, Path, Query, Retries, fun
        (200, _Headers, Body) ->
            try json:decode(Body) of
                Decoded when is_map(Decoded) -> {ok, Decoded};
                _ -> {error, #{kind => server_error, message => <<"response body was not an object">>,
                               retryable => false}}
            catch
                _:_ -> {error, #{kind => server_error, message => <<"response body was not JSON">>,
                                 retryable => false}}
            end;
        (Status, Headers, Body) ->
            {error, vpndetection_error:from_response(Status, Headers, Body)}
    end).

%% @doc Fetch the `Location' of a redirect without following it.
-spec get_redirect(map(), binary(), [{binary(), binary()}], non_neg_integer()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
get_redirect(Client, Path, Query, Retries) ->
    with_retry(Client, Path, Query, Retries, fun
        (Status, Headers, _Body) when Status >= 300, Status < 400 ->
            case lists:keyfind(<<"location">>, 1, Headers) of
                {_, Location} -> {ok, Location};
                false -> {error, #{kind => server_error, retryable => false, status => Status,
                                   message => <<"redirect carried no Location header">>}}
            end;
        (200, _Headers, _Body) ->
            {error, #{kind => server_error, retryable => false, status => 200,
                      message => <<"expected a redirect to object storage">>}};
        (Status, Headers, Body) ->
            {error, vpndetection_error:from_response(Status, Headers, Body)}
    end).

with_retry(Client, Path, Query, Retries, Handle) ->
    attempt(Client, Path, Query, Retries, Handle, 0).

attempt(Client, Path, Query, Retries, Handle, Attempt) ->
    Result = case send(Client, Path, Query) of
        {ok, #{status := Status, headers := Headers, body := Body}} -> Handle(Status, Headers, Body);
        {error, Reason} -> {error, vpndetection_error:from_transport(Reason)}
    end,
    case Result of
        {error, Error} when Attempt < Retries ->
            case maps:get(retryable, Error, false) of
                true ->
                    timer:sleep(backoff(Error, Attempt)),
                    attempt(Client, Path, Query, Retries, Handle, Attempt + 1);
                false ->
                    Result
            end;
        _ ->
            Result
    end.

%% A server-supplied Retry-After outranks our own schedule: it is the only party
%% that knows when the limit it just applied lifts.
backoff(#{retry_after := Seconds}, _Attempt) when Seconds > 0 ->
    Seconds * 1000;
backoff(_Error, Attempt) ->
    min(?BACKOFF_CAP_MS, ?BACKOFF_BASE_MS bsl Attempt).

send(#{http := Http, base_url := BaseUrl, timeout_ms := TimeoutMs} = Client, Path, Query) ->
    Url = <<BaseUrl/binary, Path/binary, (query_string(Query))/binary>>,
    Http(#{method => get, url => Url, headers => headers(Client), timeout_ms => TimeoutMs}).

headers(#{api_key := undefined, user_agent := Agent}) ->
    [{<<"accept">>, <<"application/json">>}, {<<"user-agent">>, Agent}];
headers(#{api_key := Key, user_agent := Agent}) ->
    [{<<"accept">>, <<"application/json">>}, {<<"user-agent">>, Agent},
     {<<"authorization">>, <<"Bearer ", Key/binary>>}].

query_string([]) ->
    <<>>;
query_string(Query) ->
    Encoded = [<<(escape(K))/binary, "=", (escape(V))/binary>> || {K, V} <- Query],
    <<"?", (iolist_to_binary(lists:join(<<"&">>, Encoded)))/binary>>.

%% Percent-encodes everything outside the unreserved set. IPv6 colons are escaped
%% along with the rest, which the API accepts, so one encoder covers both
%% families and a stray `/' or `?' in caller input cannot rewrite the path.
escape(Value) when is_binary(Value) ->
    <<<<(escape_byte(B))/binary>> || <<B>> <= Value>>.

escape_byte(B) when B >= $a, B =< $z; B >= $A, B =< $Z; B >= $0, B =< $9;
                    B =:= $-; B =:= $.; B =:= $_; B =:= $~ ->
    <<B>>;
escape_byte(B) ->
    <<"%", (hex(B bsr 4))/binary, (hex(B band 15))/binary>>.

hex(N) when N < 10 -> <<($0 + N)>>;
hex(N) -> <<($A + N - 10)>>.

normalize(Headers) ->
    [{list_to_binary(string:lowercase(K)), list_to_binary(V)} || {K, V} <- Headers].
