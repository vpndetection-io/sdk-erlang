%% @doc The transport: one httpc profile, retry policy, and response classification.
%%
%% A request either buffers its body or streams it into a SINK. A lookup and a
%% database listing are small enough to hold; a dataset file is not, and the
%% catalog runs to gigabytes, so the sink is a fold that never sees more than one
%% chunk at a time.
-module(vpndetection_http).

-export([ensure_ready/0, httpc_fun/0, get_json/4, get_redirect/4, get_stream/4, escape/1]).

-export_type([request/0, response/0, result/0, sink/0, fold/0, http_fun/0]).

-type request() :: #{
    method := get,
    url := binary(),
    headers := [{binary(), binary()}],
    timeout_ms := pos_integer(),
    sink => sink()
}.

%% A streamed 2xx carries `written' and `acc' and no `body'; everything else
%% carries `body'. httpc only streams a 2xx, so a refusal arrives whole and small
%% whatever was asked for.
-type result() :: #{
    headers := [{binary(), binary()}],
    status => 100..599,
    body => binary(),
    written => non_neg_integer(),
    acc => term()
}.

-type response() :: {ok, result()} | {error, term()}.

%% Answers `{ok, Acc}' or `{error, Reason}' rather than raising, so a sink that
%% cannot take the bytes (a full disk) stops the transfer as a value instead of
%% unwinding through the receive loop and abandoning the request.
-type fold() :: fun((binary(), term()) -> {ok, term()} | {error, term()}).

-type sink() :: #{fold := fold(), acc := term()}.

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
    fun send/1.

%% @doc Fetch and decode a JSON body, retrying what is worth retrying.
-spec get_json(map(), binary(), [{binary(), binary()}], non_neg_integer()) ->
    {ok, map()} | {error, vpndetection_error:error()}.
get_json(Client, Path, Query, Retries) ->
    with_retry(Client, api_request(Client, Path, Query), Retries, fun
        (#{status := 200, body := Body}) ->
            try json:decode(Body) of
                Decoded when is_map(Decoded) -> {ok, Decoded};
                _ -> {error, #{kind => server_error, message => <<"response body was not an object">>,
                               retryable => false}}
            catch
                _:_ -> {error, #{kind => server_error, message => <<"response body was not JSON">>,
                                 retryable => false}}
            end;
        (Result) ->
            {error, failure(Result)}
    end).

%% @doc Fetch the `Location' of a redirect without following it.
-spec get_redirect(map(), binary(), [{binary(), binary()}], non_neg_integer()) ->
    {ok, binary()} | {error, vpndetection_error:error()}.
get_redirect(Client, Path, Query, Retries) ->
    with_retry(Client, api_request(Client, Path, Query), Retries, fun
        (#{status := Status, headers := Headers}) when Status >= 300, Status < 400 ->
            case lists:keyfind(<<"location">>, 1, Headers) of
                {_, Location} -> {ok, Location};
                false -> {error, #{kind => server_error, retryable => false, status => Status,
                                   message => <<"redirect carried no Location header">>}}
            end;
        (#{status := 200}) ->
            {error, #{kind => server_error, retryable => false, status => 200,
                      message => <<"expected a redirect to object storage">>}};
        (Result) ->
            {error, failure(Result)}
    end).

%% @doc Stream one absolute URL through `Sink', answering what it wrote.
%%
%% No credential is attached. This is only ever pointed at the presigned link the
%% download endpoint hands out, which authorizes itself, and forwarding the API
%% key would hand it to a host with no business holding it.
-spec get_stream(map(), binary(), sink(), non_neg_integer()) ->
    {ok, #{written := non_neg_integer(), acc := term()}} | {error, vpndetection_error:error()}.
get_stream(Client, Url, Sink, Retries) ->
    Request = (transfer_request(Client, Url))#{sink => Sink},
    with_retry(Client, Request, Retries, fun
        (#{written := Written, acc := Acc}) ->
            {ok, #{written => Written, acc => Acc}};
        (Result) ->
            Error = failure(Result),
            {error, Error#{message => <<"object storage refused the download link: ",
                                        (maps:get(message, Error))/binary>>}}
    end).

-spec send(request()) -> response().
send(#{sink := Sink} = Request) ->
    stream(Request, Sink);
send(Request) ->
    whole(Request).

whole(#{url := Url, headers := Headers, timeout_ms := TimeoutMs}) ->
    %% autoredirect MUST stay false. The download endpoint answers 302 to
    %% object storage, and following it would pull a dataset that routinely
    %% runs to gigabytes into memory as one binary.
    HttpOpts = [{timeout, TimeoutMs}, {connect_timeout, TimeoutMs}, {autoredirect, false}],
    case httpc:request(get, httpc_request(Url, Headers), HttpOpts,
                       [{body_format, binary}], ?PROFILE) of
        {ok, {{_Version, Status, _Phrase}, RespHeaders, Body}} ->
            {ok, #{status => Status, headers => normalize(RespHeaders), body => Body}};
        {error, Reason} ->
            {error, Reason}
    end.

%% `{stream, {self, once}}' rather than `{stream, self}': the once form makes the
%% handler wait for `httpc:stream_next/1' before sending the next chunk, so the
%% body cannot outrun the sink. Measured on a 192 MB body with a sink slower than
%% the socket, `{stream, self}' grows the binary heap by the whole body while the
%% once form stays flat at one chunk.
%%
%% The whole-request timeout is `infinity' and the bound is per chunk instead: 30
%% seconds is a sane deadline for a lookup and the wrong one for a gigabyte,
%% while a transfer that has stopped making progress is stalled at any size.
stream(#{url := Url, headers := Headers, timeout_ms := TimeoutMs}, Sink) ->
    HttpOpts = [{timeout, infinity}, {connect_timeout, TimeoutMs}, {autoredirect, false}],
    Options = [{sync, false}, {stream, {self, once}}, {body_format, binary}, {receiver, self()}],
    case httpc:request(get, httpc_request(Url, Headers), HttpOpts, Options, ?PROFILE) of
        {ok, Id} -> await_start(Id, Sink, TimeoutMs);
        {error, Reason} -> {error, Reason}
    end.

await_start(Id, #{fold := Fold, acc := Acc}, IdleMs) ->
    receive
        {http, {Id, stream_start, Headers, Handler}} ->
            httpc:stream_next(Handler),
            drain(Id, Handler, normalize(Headers), Fold, Acc, 0, IdleMs);
        %% Not a 2xx. httpc streams only a successful body, so a refusal arrives
        %% whole, and a refusal body is small by construction.
        {http, {Id, {{_Version, Status, _Phrase}, Headers, Body}}} ->
            {ok, #{status => Status, headers => normalize(Headers), body => Body}};
        {http, {Id, {error, Reason}}} ->
            {error, Reason}
    after IdleMs ->
        cancel(Id),
        {error, timeout}
    end.

drain(Id, Handler, Headers, Fold, Acc, Written, IdleMs) ->
    receive
        {http, {Id, stream, Chunk}} ->
            case Fold(Chunk, Acc) of
                {ok, Next} ->
                    httpc:stream_next(Handler),
                    drain(Id, Handler, Headers, Fold, Next, Written + byte_size(Chunk), IdleMs);
                {error, Reason} ->
                    cancel(Id),
                    {error, {sink_failed, Reason}}
            end;
        {http, {Id, stream_end, _Trailers}} ->
            {ok, #{headers => Headers, written => Written, acc => Acc}};
        %% A body that stops short of its declared content-length reaches here as
        %% an error rather than an early `stream_end', so a truncated transfer
        %% fails instead of quietly producing a short file.
        {http, {Id, {error, Reason}}} ->
            broke(Written, Reason)
    after IdleMs ->
        cancel(Id),
        broke(Written, timeout)
    end.

%% Once anything has reached the sink the failure must NOT be retried, whatever
%% the cause: those bytes are written, and a second attempt would append a second
%% copy of the body behind them. Before the first chunk there is nothing to undo,
%% so the plain reason is returned and the usual retry rules apply.
broke(0, Reason) ->
    {error, Reason};
broke(Written, Reason) ->
    {error, {transfer_failed, Written, Reason}}.

%% cancel_request is asynchronous, so chunks already on their way would otherwise
%% be left in the mailbox of whichever process called the library.
cancel(Id) ->
    _ = httpc:cancel_request(Id, ?PROFILE),
    flush(Id).

flush(Id) ->
    receive
        {http, {Id, _}} -> flush(Id);
        {http, {Id, _, _}} -> flush(Id);
        {http, {Id, _, _, _}} -> flush(Id)
    after 0 ->
        ok
    end.

httpc_request(Url, Headers) ->
    {binary_to_list(Url), [{binary_to_list(K), binary_to_list(V)} || {K, V} <- Headers]}.

with_retry(Client, Request, Retries, Handle) ->
    attempt(Client, Request, Retries, Handle, 0).

attempt(#{http := Http} = Client, Request, Retries, Handle, Attempt) ->
    Result = case Http(Request) of
        {ok, Response} -> Handle(Response);
        {error, Reason} -> {error, vpndetection_error:from_transport(Reason)}
    end,
    case Result of
        {error, Error} when Attempt < Retries ->
            case maps:get(retryable, Error, false) of
                true ->
                    timer:sleep(backoff(Error, Attempt)),
                    attempt(Client, Request, Retries, Handle, Attempt + 1);
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

failure(#{status := Status, headers := Headers} = Result) ->
    vpndetection_error:from_response(Status, Headers, maps:get(body, Result, <<>>)).

api_request(#{base_url := BaseUrl, timeout_ms := TimeoutMs} = Client, Path, Query) ->
    Url = <<BaseUrl/binary, Path/binary, (query_string(Query))/binary>>,
    #{method => get, url => Url, headers => headers(Client), timeout_ms => TimeoutMs}.

transfer_request(#{timeout_ms := TimeoutMs, user_agent := Agent}, Url) ->
    #{method => get, url => Url, timeout_ms => TimeoutMs,
      headers => [{<<"accept">>, <<"*/*">>}, {<<"user-agent">>, Agent}]}.

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
