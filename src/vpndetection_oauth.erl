%% @doc The OAuth device flow behind the `oauth_*' functions on `vpndetection'.
%%
%% No request made here carries the API key the client was built with, and a
%% client built without one works exactly the same. Every answer is a map whose
%% keys come from a fixed allowlist of atoms; members the server adds later are
%% dropped rather than minted.
-module(vpndetection_oauth).

-export([metadata/2, device_authorization/4, exchange_device_code/4,
         exchange_refresh_token/4, revoke/4, poll_device_token/4]).

-export_type([metadata/0, device_authorization/0, token_response/0]).

-type metadata() :: #{
    issuer := binary(),
    authorization_endpoint := binary(),
    token_endpoint := binary(),
    device_authorization_endpoint => binary(),
    revocation_endpoint => binary(),
    scopes_supported => [binary()],
    response_types_supported => [binary()],
    grant_types_supported => [binary()],
    code_challenge_methods_supported => [binary()],
    token_endpoint_auth_methods_supported => [binary()],
    authorization_response_iss_parameter_supported => boolean(),
    service_documentation => binary()
}.

-type device_authorization() :: #{
    device_code := binary(),
    user_code := binary(),
    verification_uri := binary(),
    verification_uri_complete => binary(),
    expires_in := integer(),
    interval := integer()
}.

-type token_response() :: #{
    access_token := binary(),
    token_type := binary(),
    expires_in := integer(),
    refresh_token => binary(),
    scope => binary(),
    apikey_id => binary(),
    apikey => binary()
}.

-define(DEVICE_CODE_GRANT, <<"urn:ietf:params:oauth:grant-type:device_code">>).

%% {wire name, key, type, required}
-define(METADATA, [
    {<<"issuer">>, issuer, string, true},
    {<<"authorization_endpoint">>, authorization_endpoint, string, true},
    {<<"token_endpoint">>, token_endpoint, string, true},
    {<<"device_authorization_endpoint">>, device_authorization_endpoint, string, false},
    {<<"revocation_endpoint">>, revocation_endpoint, string, false},
    {<<"scopes_supported">>, scopes_supported, strings, false},
    {<<"response_types_supported">>, response_types_supported, strings, false},
    {<<"grant_types_supported">>, grant_types_supported, strings, false},
    {<<"code_challenge_methods_supported">>, code_challenge_methods_supported, strings, false},
    {<<"token_endpoint_auth_methods_supported">>, token_endpoint_auth_methods_supported, strings, false},
    {<<"authorization_response_iss_parameter_supported">>, authorization_response_iss_parameter_supported,
     boolean, false},
    {<<"service_documentation">>, service_documentation, string, false}
]).
-define(DEVICE_AUTHORIZATION, [
    {<<"device_code">>, device_code, string, true},
    {<<"user_code">>, user_code, string, true},
    {<<"verification_uri">>, verification_uri, string, true},
    {<<"verification_uri_complete">>, verification_uri_complete, string, false},
    {<<"expires_in">>, expires_in, integer, true},
    {<<"interval">>, interval, integer, true}
]).
-define(TOKEN_RESPONSE, [
    {<<"access_token">>, access_token, string, true},
    {<<"token_type">>, token_type, string, true},
    {<<"expires_in">>, expires_in, integer, true},
    {<<"refresh_token">>, refresh_token, string, false},
    {<<"scope">>, scope, string, false},
    {<<"mslm:apikey_id">>, apikey_id, string, false},
    {<<"mslm:apikey">>, apikey, string, false}
]).

-spec metadata(map(), map()) -> {ok, metadata()} | {error, vpndetection_error:error()}.
metadata(Client, Options) ->
    Bound = bound(Client, Options),
    Path = <<"/.well-known/oauth-authorization-server">>,
    Request = vpndetection_http:oauth_request(Bound, Path, undefined),
    vpndetection_http:oauth(Bound, Request, maps:get(retries, Client), decoder(?METADATA)).

-spec device_authorization(map(), binary(), [{binary(), binary()}], map()) ->
    {ok, device_authorization()} | {error, vpndetection_error:error()}.
device_authorization(Client, ClientId, Extra, Options) ->
    Bound = bound(Client, Options),
    Form = [{<<"client_id">>, ClientId} | Extra],
    Request = vpndetection_http:oauth_request(Bound, <<"/oauth/device_authorization">>, Form),
    vpndetection_http:oauth(Bound, Request, maps:get(retries, Client), decoder(?DEVICE_AUTHORIZATION)).

%% Never retried: the server spends the code when it answers, so a retry after a
%% lost success could only fail and lose the tokens.
-spec exchange_device_code(map(), binary(), binary(), map()) ->
    {ok, token_response()} | {error, vpndetection_error:error()}.
exchange_device_code(Client, ClientId, DeviceCode, Options) ->
    exchange(Client, [{<<"grant_type">>, ?DEVICE_CODE_GRANT}, {<<"device_code">>, DeviceCode},
                      {<<"client_id">>, ClientId}], Options).

-spec exchange_refresh_token(map(), binary(), binary(), map()) ->
    {ok, token_response()} | {error, vpndetection_error:error()}.
exchange_refresh_token(Client, ClientId, RefreshToken, Options) ->
    exchange(Client, [{<<"grant_type">>, <<"refresh_token">>}, {<<"refresh_token">>, RefreshToken},
                      {<<"client_id">>, ClientId}], Options).

%% Revoking twice is revoking once, so this retries; the body is never read.
-spec revoke(map(), binary(), binary(), map()) -> ok | {error, vpndetection_error:error()}.
revoke(Client, ClientId, Token, Options) ->
    Bound = bound(Client, Options),
    Form = [{<<"token">>, Token}, {<<"client_id">>, ClientId}],
    Request = vpndetection_http:oauth_request(Bound, <<"/oauth/revoke">>, Form),
    Ignore = fun(_Status, _Body) -> {ok, ok} end,
    case vpndetection_http:oauth(Bound, Request, maps:get(retries, Client), Ignore) of
        {ok, ok} -> ok;
        {error, Error} -> {error, Error}
    end.

%% Waits the interval BEFORE every exchange, the first included, so the server's
%% gap between two polls is never shorter than it. A `slow_down' widens the wait
%% by five seconds for the rest of the call; any answer but that and
%% `authorization_pending' ends it. Every wait ends at the local deadline at the
%% latest, so an interval longer than the time left sleeps only until the deadline
%% and the local expiry follows with no request sent.
-spec poll_device_token(map(), binary(), device_authorization(), map()) ->
    {ok, token_response()} | {error, vpndetection_error:error()}.
poll_device_token(Client, ClientId, #{device_code := Code, expires_in := ExpiresIn} = Device, Options) ->
    {Wait, Now} = clock(Options),
    Deadline = Now() + ExpiresIn * 1000,
    poll(Client, ClientId, Code, Options, {Wait, Now, Deadline}, first_interval(Device)).

poll(Client, ClientId, Code, Options, {Wait, Now, Deadline} = Clock, Interval) ->
    Wait(min(Interval * 1000, max(Deadline - Now(), 0))),
    case Now() >= Deadline of
        true ->
            {error, vpndetection_error:local_expiry()};
        false ->
            case exchange_device_code(Client, ClientId, Code, Options) of
                {error, #{error_code := <<"authorization_pending">>}} ->
                    poll(Client, ClientId, Code, Options, Clock, Interval);
                {error, #{error_code := <<"slow_down">>}} ->
                    poll(Client, ClientId, Code, Options, Clock, Interval + 5);
                Outcome ->
                    Outcome
            end
    end.

first_interval(#{interval := Interval}) when is_integer(Interval), Interval >= 1 -> Interval;
first_interval(_Device) -> 5.

exchange(Client, Form, Options) ->
    Bound = bound(Client, Options),
    Request = vpndetection_http:oauth_request(Bound, <<"/oauth/token">>, Form),
    vpndetection_http:oauth(Bound, Request, 0, decoder(?TOKEN_RESPONSE)).

%% The client with this call's `timeout_ms' in place of its own.
bound(Client, Options) ->
    Client#{timeout_ms := maps:get(timeout_ms, Options, maps:get(timeout_ms, Client))}.

%% Only the declared members are read, each checked against its type, so an
%% absent member stays absent and an empty `scope' stays an empty binary. A 2xx
%% that is not its type is the server's fault, and says so with its status.
decoder(Members) ->
    fun(Status, Body) ->
        try json:decode(Body) of
            Decoded when is_map(Decoded) -> members(Members, Decoded, Status, #{});
            _ -> {error, malformed(Status, <<"the answer was not a JSON object">>)}
        catch
            _:_ -> {error, malformed(Status, <<"the answer was not JSON">>)}
        end
    end.

members([], _Body, _Status, Acc) ->
    {ok, Acc};
members([{Wire, Key, Type, Required} | Rest], Body, Status, Acc) ->
    case {maps:get(Wire, Body, null), Required} of
        {null, false} ->
            members(Rest, Body, Status, Acc);
        {null, true} ->
            {error, malformed(Status, <<"the answer carried no ", Wire/binary>>)};
        {Value, _} ->
            case typed(Type, Value) of
                true -> members(Rest, Body, Status, Acc#{Key => Value});
                false -> {error, malformed(Status, <<"the answer's ", Wire/binary, " has the wrong type">>)}
            end
    end.

typed(string, Value) -> is_binary(Value);
typed(integer, Value) -> is_integer(Value);
typed(boolean, Value) -> is_boolean(Value);
typed(strings, Value) -> is_list(Value) andalso lists:all(fun erlang:is_binary/1, Value).

malformed(Status, Message) ->
    #{kind => server_error, retryable => false, status => Status, message => Message}.

-ifdef(TEST).
%% A test replaces the poll's wait and its monotonic clock together.
clock(Options) ->
    maps:get(clock, Options, {fun timer:sleep/1, fun now_ms/0}).
-else.
clock(_Options) ->
    {fun timer:sleep/1, fun now_ms/0}.
-endif.

now_ms() ->
    erlang:monotonic_time(millisecond).
