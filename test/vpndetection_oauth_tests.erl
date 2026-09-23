%% The `oauth_*' functions against the shared corpus, over the real httpc
%% transport and a real socket, so the method, path, headers and form are read
%% where they ARRIVE.
%%
%% Every call runs in a process of its own that the test kills when it has not
%% settled in time: a loop in the code under test must fail the test, never hang
%% it, and the poll's fake wait and the origin both stop answering past a cap.
-module(vpndetection_oauth_tests).

-include_lib("eunit/include/eunit.hrl").

-define(CLIENT_ID, <<"vpndetection-cli">>).
-define(BOUND_MS, 15000).
-define(WAIT_CAP, 30).
%% The corpus's metadata document still names a member the published spec dropped.
-define(NOT_IN_SPEC, [<<"client_id_metadata_document_supported">>]).

each_operation_requests_its_own_method_and_path_test_() ->
    {timeout, 60, fun() ->
        Operations = [
            {<<"metadata">>, <<"metadata">>, #{}},
            {<<"deviceAuthorization">>, <<"deviceAuthorization">>, #{<<"clientId">> => ?CLIENT_ID}},
            {<<"token">>, <<"exchangeDeviceCode">>,
             #{<<"clientId">> => ?CLIENT_ID, <<"deviceCode">> => <<"mo_dc_x">>}},
            {<<"token">>, <<"exchangeRefreshToken">>,
             #{<<"clientId">> => ?CLIENT_ID, <<"refreshToken">> => <<"mo_rt_x">>}},
            {<<"revoke">>, <<"revoke">>, #{<<"clientId">> => ?CLIENT_ID, <<"token">> => <<"mo_rt_x">>}}
        ],
        [begin
             {Origin, Client} = keyless([success_for(Endpoint)]),
             Outcome = bounded(fun() -> call(Client, Operation, Args) end),
             ?assertMatch({Operation, {ok, _}}, {Operation, Outcome}),
             [Seen] = vpndetection_oauth_origin:requests(Origin),
             assert_requested(Endpoint, Seen, Operation),
             vpndetection_oauth_origin:stop(Origin)
         end || {Endpoint, Operation, Args} <- Operations]
    end}.

every_form_leaves_encoded_exactly_as_the_corpus_says_test_() ->
    {timeout, 60, fun() ->
        #{<<"contentType">> := Type, <<"cases">> := Cases} = oauth(<<"forms">>),
        [begin
             {Origin, Client} = keyless([success_for(Endpoint)]),
             ?assertMatch({Name, {ok, _}}, {Name, bounded(fun() -> call(Client, Operation, Args) end)}),
             [#{headers := Headers, body := Body} = Seen] = vpndetection_oauth_origin:requests(Origin),
             assert_requested(Endpoint, Seen, Name),
             Sent = proplists:get_value(<<"content-type">>, Headers, <<>>),
             ?assertEqual({Name, {0, byte_size(Type)}}, {Name, binary:match(Sent, Type)}),
             Pairs = uri_string:dissect_query(Body),
             ?assertEqual({Name, Fields}, {Name, maps:from_list(Pairs)}),
             ?assertEqual({Name, map_size(Fields)}, {Name, length(Pairs)}),
             vpndetection_oauth_origin:stop(Origin)
         end || #{<<"name">> := Name, <<"operation">> := Operation, <<"endpoint">> := Endpoint,
                  <<"args">> := Args, <<"fields">> := Fields} <- Cases]
    end}.

every_corpus_response_decodes_with_absent_left_absent_test_() ->
    {timeout, 60, fun() ->
        Responses = oauth(<<"responses">>),
        Calls = [
            {<<"metadata">>, fun(Client) -> vpndetection:oauth_metadata(Client) end},
            {<<"deviceAuthorization">>,
             fun(Client) -> vpndetection:oauth_device_authorization(Client, ?CLIENT_ID) end},
            {<<"token">>,
             fun(Client) -> vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, <<"mo_dc_x">>) end}
        ],
        [begin
             {Origin, Client} = keyless([Case]),
             {ok, Answer} = bounded(fun() -> Call(Client) end),
             #{<<"present">> := Present, <<"absent">> := Absent} = Expect,
             [?assertEqual({Name, Member, Value}, {Name, Member, maps:get(atom(Member), Answer, missing)})
              || Member := Value <- Present, not lists:member(Member, ?NOT_IN_SPEC)],
             [?assertEqual({Name, Member, error}, {Name, Member, maps:find(atom(Member), Answer)})
              || Member <- Absent],
             vpndetection_oauth_origin:stop(Origin)
         end || {Type, Call} <- Calls,
                #{<<"name">> := Name, <<"expect">> := Expect} = Case <- maps:get(Type, Responses)]
    end}.

revoke_reads_no_body_test_() ->
    {timeout, 60, fun() ->
        [begin
             {Origin, Client} = keyless([Case]),
             ?assertEqual({Name, ok}, {Name, bounded(fun() ->
                 vpndetection:oauth_revoke(Client, ?CLIENT_ID, <<"mo_rt_x">>)
             end)}),
             vpndetection_oauth_origin:stop(Origin)
         end || #{<<"name">> := Name} = Case <- maps:get(<<"revoke">>, oauth(<<"responses">>))]
    end}.

every_corpus_error_is_classified_test_() ->
    {timeout, 60, fun() ->
        [begin
             {Origin, Client} = keyless([Case]),
             {error, Error} = bounded(fun() ->
                 vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, <<"mo_dc_x">>)
             end),
             assert_error(Name, Expect, Error),
             vpndetection_oauth_origin:stop(Origin)
         end || #{<<"name">> := Name, <<"expect">> := Expect} = Case <- cases(<<"errors">>)]
    end}.

%% The request count is asserted BEFORE the outcome: an extra retry would pick up
%% the origin's fallback 503 and fail on the error's shape, the wrong reason.
only_the_idempotent_operations_retry_test_() ->
    {timeout, 60, fun() ->
        [begin
             Origin = vpndetection_oauth_origin:start(Responses),
             Client = vpndetection:new(#{base_url => vpndetection_oauth_origin:base_url(Origin),
                                         cache => false, timeout_ms => 2000}),
             Outcome = bounded(fun() -> call(Client, Operation, Args) end),
             ?assertEqual({Name, maps:get(<<"requests">>, Expect)},
                          {Name, length(vpndetection_oauth_origin:requests(Origin))}),
             assert_outcome(Name, Expect, Outcome),
             vpndetection_oauth_origin:stop(Origin)
         end || #{<<"name">> := Name, <<"operation">> := Operation, <<"args">> := Args,
                  <<"responses">> := Responses, <<"expect">> := Expect} <- cases(<<"retries">>)]
    end}.

poll_device_token_follows_every_corpus_case_test_() ->
    {timeout, 120, fun() ->
        [begin
             {Origin, Client} = keyless(Responses),
             {Clock, Fake} = fake_clock(),
             Outcome = bounded(fun() ->
                 vpndetection:oauth_poll_device_token(Client, ClientId, device(Device), #{clock => Fake})
             end),
             Seen = vpndetection_oauth_origin:requests(Origin),
             ?assertEqual({Name, maps:get(<<"requests">>, Expect)}, {Name, length(Seen)}),
             [assert_polled(Name, ClientId, Device, Request) || Request <- Seen],
             ?assertEqual({Name, [W * 1000 || W <- maps:get(<<"waits">>, Expect)]}, {Name, waits(Clock)}),
             assert_poll_outcome(Name, Expect, Outcome),
             vpndetection_oauth_origin:stop(Origin)
         end || #{<<"name">> := Name, <<"clientId">> := ClientId, <<"device">> := Device,
                  <<"responses">> := Responses, <<"expect">> := Expect} <- cases(<<"poll">>)]
    end}.

no_oauth_request_carries_the_api_key_test_() ->
    {timeout, 60, fun() ->
        #{<<"apiKey">> := Key, <<"forbiddenHeaders">> := Forbidden, <<"forbiddenQuery">> := ForbiddenQuery} =
            oauth(<<"noCredential">>),
        Token = success_for(<<"token">>),
        Script = [success_for(<<"metadata">>), success_for(<<"deviceAuthorization">>), Token, Token,
                  success_for(<<"revoke">>), Token],
        Origin = vpndetection_oauth_origin:start(Script),
        Client = vpndetection:new(#{api_key => Key, base_url => vpndetection_oauth_origin:base_url(Origin),
                                    cache => false, timeout_ms => 2000}),
        {_Clock, Fake} = fake_clock(),

        Outcome = bounded(fun() ->
            {ok, _} = vpndetection:oauth_metadata(Client),
            {ok, Device} = vpndetection:oauth_device_authorization(Client, ?CLIENT_ID,
                                                                  #{scope => <<"account.read">>}),
            {ok, _} = vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, <<"mo_dc_x">>),
            {ok, _} = vpndetection:oauth_exchange_refresh_token(Client, ?CLIENT_ID, <<"mo_rt_x">>),
            ok = vpndetection:oauth_revoke(Client, ?CLIENT_ID, <<"mo_rt_x">>),
            vpndetection:oauth_poll_device_token(Client, ?CLIENT_ID, Device, #{clock => Fake})
        end),

        ?assertMatch({ok, _}, Outcome),
        Seen = vpndetection_oauth_origin:requests(Origin),
        ?assertEqual(6, length(Seen)),
        [begin
             [?assertEqual({Path, Name, absent}, {Path, Name, proplists:get_value(Name, Headers, absent)})
              || Name <- Forbidden],
             Params = uri_string:dissect_query(Query),
             [?assertNot(lists:keymember(Name, 1, Params)) || Name <- ForbiddenQuery],
             Carried = [Part || Part <- [Path, Query, Body | [V || {_, V} <- Headers]],
                                binary:match(Part, Key) =/= nomatch],
             ?assertEqual({Path, []}, {Path, Carried})
         end || #{path := Path, query := Query, headers := Headers, body := Body} <- Seen],
        vpndetection:close(Client),
        vpndetection_oauth_origin:stop(Origin)
    end}.

a_2xx_that_is_not_its_type_is_an_ordinary_server_error_test_() ->
    {timeout, 60, fun() ->
        Answers = [
            #{<<"status">> => 200,
              <<"body">> => #{<<"token_type">> => <<"Bearer">>, <<"expires_in">> => 3600}},
            #{<<"status">> => 200, <<"body">> => #{<<"access_token">> => <<"mo_at_x">>,
                                                   <<"token_type">> => <<"Bearer">>,
                                                   <<"expires_in">> => <<"3600">>}},
            #{<<"status">> => 200, <<"rawBody">> => <<"this is not JSON">>}
        ],
        [begin
             {Origin, Client} = keyless([Answer]),
             Outcome = bounded(fun() ->
                 vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, <<"mo_dc_x">>)
             end),
             ?assertEqual({Answer, 1}, {Answer, length(vpndetection_oauth_origin:requests(Origin))}),
             ?assertMatch({error, #{kind := server_error, status := 200}}, Outcome),
             {error, Error} = Outcome,
             ?assertNot(maps:is_key(error_code, Error)),
             vpndetection_oauth_origin:stop(Origin)
         end || Answer <- Answers]
    end}.

%% No corpus case: every response there decodes. One member left out per case,
%% since a body missing several at once passes against a decoder that defaults
%% any single one of them.
an_answer_missing_any_one_required_member_is_an_ordinary_server_error_test_() ->
    {timeout, 60, fun() ->
        Responses = oauth(<<"responses">>),
        Every = lists:foldl(fun(Type, Acc) ->
            [#{<<"body">> := Body} | _] = maps:get(Type, Responses),
            maps:merge(Acc, Body)
        end, #{}, [<<"metadata">>, <<"deviceAuthorization">>, <<"token">>]),
        Required = [
            {<<"metadata">>, [<<"issuer">>, <<"authorization_endpoint">>, <<"token_endpoint">>]},
            {<<"deviceAuthorization">>, [<<"device_code">>, <<"user_code">>, <<"verification_uri">>,
                                         <<"expires_in">>, <<"interval">>]},
            {<<"exchangeDeviceCode">>, [<<"access_token">>, <<"token_type">>, <<"expires_in">>]}
        ],
        Args = #{<<"clientId">> => ?CLIENT_ID, <<"deviceCode">> => <<"mo_dc_x">>},
        [begin
             {Origin, Client} = keyless([#{<<"status">> => 200, <<"body">> => maps:remove(Member, Every)}]),
             Outcome = bounded(fun() -> call(Client, Operation, Args) end),
             ?assertEqual({Operation, Member, 1},
                          {Operation, Member, length(vpndetection_oauth_origin:requests(Origin))}),
             ?assertMatch({Operation, Member, {error, #{kind := server_error, status := 200}}},
                          {Operation, Member, Outcome}),
             {error, Error} = Outcome,
             ?assertNot(maps:is_key(error_code, Error)),
             vpndetection_oauth_origin:stop(Origin)
         end || {Operation, Members} <- Required, Member <- Members]
    end}.

%% Against an origin that stalls past both bounds, each function's own 300 ms
%% fires rather than the client's 4 s. The poll's bounds its exchange.
every_oauth_function_takes_a_per_call_timeout_test_() ->
    {timeout, 90, fun() ->
        Origin = vpndetection_origin:start(#{delay_ms => 8000}),
        Client = vpndetection:new(#{base_url => vpndetection_origin:base_url(Origin),
                                    cache => false, retries => 0, timeout_ms => 4000}),
        {_Clock, Fake} = fake_clock(),
        [#{<<"device">> := Device} | _] = maps:get(<<"cases">>, oauth(<<"poll">>)),
        PerCall = #{timeout_ms => 300},
        Calls = [
            {metadata, fun() -> vpndetection:oauth_metadata(Client, PerCall) end},
            {device_authorization,
             fun() -> vpndetection:oauth_device_authorization(Client, ?CLIENT_ID, PerCall) end},
            {exchange_device_code,
             fun() -> vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, <<"mo_dc">>, PerCall) end},
            {exchange_refresh_token,
             fun() -> vpndetection:oauth_exchange_refresh_token(Client, ?CLIENT_ID, <<"mo_rt">>, PerCall) end},
            {revoke, fun() -> vpndetection:oauth_revoke(Client, ?CLIENT_ID, <<"mo_rt_x">>, PerCall) end},
            {poll_device_token, fun() ->
                Options = PerCall#{clock => Fake},
                vpndetection:oauth_poll_device_token(Client, ?CLIENT_ID, device(Device), Options)
            end}
        ],
        [begin
             {Micros, Outcome} = timer:tc(fun() -> bounded(Call) end),
             ?assertMatch({Name, {error, #{kind := network}}}, {Name, Outcome}),
             ?assert(Micros < 2000000)
         end || {Name, Call} <- Calls],
        vpndetection_origin:stop(Origin)
    end}.

call(Client, <<"metadata">>, _Args) ->
    vpndetection:oauth_metadata(Client);
call(Client, <<"deviceAuthorization">>, #{<<"clientId">> := ClientId} = Args) ->
    Named = [{<<"scope">>, scope}, {<<"resource">>, resource}],
    Options = maps:from_list([{Key, Value} || {Name, Key} <- Named, Value <- [maps:get(Name, Args, undefined)],
                                              Value =/= undefined]),
    vpndetection:oauth_device_authorization(Client, ClientId, Options);
call(Client, <<"exchangeDeviceCode">>, #{<<"clientId">> := ClientId, <<"deviceCode">> := Code}) ->
    vpndetection:oauth_exchange_device_code(Client, ClientId, Code);
call(Client, <<"exchangeRefreshToken">>, #{<<"clientId">> := ClientId, <<"refreshToken">> := Token}) ->
    vpndetection:oauth_exchange_refresh_token(Client, ClientId, Token);
call(Client, <<"revoke">>, #{<<"clientId">> := ClientId, <<"token">> := Token}) ->
    case vpndetection:oauth_revoke(Client, ClientId, Token) of
        ok -> {ok, revoked};
        Other -> Other
    end.

assert_requested(Endpoint, #{method := Method, path := Path}, Name) ->
    #{<<"method">> := Expected, <<"path">> := ExpectedPath} = maps:get(Endpoint, oauth(<<"endpoints">>)),
    ?assertEqual({Name, Expected, ExpectedPath}, {Name, Method, Path}).

assert_polled(Name, ClientId, #{<<"device_code">> := Code}, #{body := Body} = Request) ->
    assert_requested(<<"token">>, Request, Name),
    Fields = #{<<"grant_type">> => <<"urn:ietf:params:oauth:grant-type:device_code">>,
               <<"device_code">> => Code, <<"client_id">> => ClientId},
    ?assertEqual({Name, Fields}, {Name, maps:from_list(uri_string:dissect_query(Body))}).

assert_error(Name, #{<<"type">> := <<"client">>} = Expect, Error) ->
    assert_ordinary(Name, Expect, Error),
    ?assertEqual({Name, false}, {Name, maps:is_key(error_code, Error)});
assert_error(Name, #{<<"type">> := Type} = Expect, Error) ->
    assert_ordinary(Name, Expect, Error),
    Code = maps:get(<<"errorCode">>, Expect),
    ?assertEqual({Name, Code}, {Name, maps:get(error_code, Error, missing)}),
    ?assertEqual({Name, Type}, {Name, type_of(Code)}),
    Description = case maps:get(<<"errorDescription">>, Expect) of
        null -> error;
        Text -> {ok, Text}
    end,
    ?assertEqual({Name, Description}, {Name, maps:find(error_description, Error)}),
    ?assertEqual({Name, maps:get(<<"message">>, Expect)}, {Name, maps:get(message, Error)}).

assert_ordinary(Name, Expect, Error) ->
    ?assertEqual({Name, maps:get(<<"status">>, Expect)}, {Name, maps:get(status, Error, null)}),
    Kind = binary_to_existing_atom(maps:get(<<"kind">>, Expect)),
    ?assertEqual({Name, Kind}, {Name, maps:get(kind, Error)}),
    ?assertEqual({Name, maps:get(<<"retryable">>, Expect)}, {Name, maps:get(retryable, Error)}).

assert_outcome(Name, #{<<"outcome">> := <<"ok">>}, Outcome) ->
    ?assertMatch({Name, {ok, _}}, {Name, Outcome});
assert_outcome(Name, #{<<"outcome">> := <<"client">>, <<"kind">> := Kind}, Outcome) ->
    ?assertMatch({Name, {error, _}}, {Name, Outcome}),
    {error, Error} = Outcome,
    ?assertEqual({Name, binary_to_existing_atom(Kind), false},
                 {Name, maps:get(kind, Error), maps:is_key(error_code, Error)});
assert_outcome(Name, #{<<"outcome">> := <<"oauth">>, <<"errorCode">> := Code}, Outcome) ->
    ?assertMatch({Name, {error, #{error_code := Code}}}, {Name, Outcome}).

%% The corpus's four outcomes. Erlang has no error subtypes, so `accessDenied'
%% and `expiredToken' are the refusals with those codes.
assert_poll_outcome(Name, #{<<"outcome">> := <<"token">>} = Expect, Outcome) ->
    ?assertMatch({Name, {ok, _}}, {Name, Outcome}),
    {ok, Token} = Outcome,
    [?assertEqual({Name, Member, Value}, {Name, Member, maps:get(atom(Member), Token, missing)})
     || Member := Value <- maps:get(<<"token">>, Expect, #{})];
assert_poll_outcome(Name, #{<<"outcome">> := <<"client">>} = Expect, Outcome) ->
    ?assertMatch({Name, {error, _}}, {Name, Outcome}),
    {error, Error} = Outcome,
    Kind = binary_to_existing_atom(maps:get(<<"kind">>, Expect)),
    ?assertEqual({Name, Kind, maps:get(<<"retryable">>, Expect)},
                 {Name, maps:get(kind, Error), maps:get(retryable, Error)}),
    ?assertNot(maps:is_key(error_code, Error));
assert_poll_outcome(Name, #{<<"outcome">> := Type} = Expect, Outcome) ->
    ?assertMatch({Name, {error, #{error_code := _}}}, {Name, Outcome}),
    {error, Error} = Outcome,
    Code = maps:get(error_code, Error),
    case Type of
        <<"oauth">> -> ?assertEqual({Name, maps:get(<<"errorCode">>, Expect)}, {Name, Code});
        _ -> ?assertEqual({Name, Type}, {Name, type_of(Code)})
    end,
    case maps:find(<<"status">>, Expect) of
        {ok, Status} -> ?assertEqual({Name, Status}, {Name, maps:get(status, Error, null)});
        error -> ok
    end.

type_of(<<"access_denied">>) -> <<"accessDenied">>;
type_of(<<"expired_token">>) -> <<"expiredToken">>;
type_of(_Code) -> <<"oauth">>.

keyless(Script) ->
    Origin = vpndetection_oauth_origin:start(Script),
    {Origin, vpndetection:new(#{base_url => vpndetection_oauth_origin:base_url(Origin),
                                cache => false, timeout_ms => 2000})}.

success_for(Endpoint) ->
    [First | _] = maps:get(Endpoint, oauth(<<"responses">>)),
    First.

%% The corpus's device authorization, as `oauth_device_authorization' answers one.
device(Device) ->
    maps:from_list([{atom(K), V} || K := V <- Device]).

%% Runs the call in a process of its own and fails the test from OUTSIDE when it
%% has not settled, killing it: a bound raised inside the loop could be caught.
bounded(Fun) ->
    Parent = self(),
    Ref = make_ref(),
    {Pid, Monitor} = spawn_monitor(fun() -> Parent ! {Ref, Fun()} end),
    receive
        {Ref, Result} ->
            erlang:demonitor(Monitor, [flush]),
            Result;
        {'DOWN', Monitor, process, Pid, Reason} ->
            error({call_crashed, Reason})
    after ?BOUND_MS ->
        exit(Pid, kill),
        error(still_running_after_15s_which_is_a_loop_that_never_ends)
    end.

%% Replaces BOTH the poll's wait and its clock, so the waits are asserted exactly
%% and cost nothing. Past ?WAIT_CAP waits it never answers, which parks a runaway
%% poll where `bounded/1' ends it.
fake_clock() ->
    Pid = spawn_link(fun() -> clock(0, []) end),
    {Pid, {fun(Ms) -> ask_clock(Pid, {wait, Ms}) end, fun() -> ask_clock(Pid, now) end}}.

clock(Now, Waits) ->
    receive
        {_From, _Ref, {wait, _Ms}} when length(Waits) >= ?WAIT_CAP ->
            clock(Now, Waits);
        {From, Ref, {wait, Ms}} ->
            From ! {Ref, ok},
            clock(Now + Ms, [Ms | Waits]);
        {From, Ref, now} ->
            From ! {Ref, Now},
            clock(Now, Waits);
        {From, Ref, waits} ->
            From ! {Ref, lists:reverse(Waits)},
            clock(Now, Waits)
    end.

waits(Clock) ->
    ask_clock(Clock, waits).

ask_clock(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {self(), Ref, Message},
    receive
        {Ref, Reply} -> Reply
    end.

oauth(Key) ->
    maps:get(Key, maps:get(<<"oauth">>, testdata())).

cases(Key) ->
    maps:get(<<"cases">>, oauth(Key)).

testdata() ->
    {ok, Raw} = file:read_file("testdata/testdata.json"),
    json:decode(Raw).

%% Corpus member names are the surfaced ones, which the decoder holds as atoms;
%% an existing-atom lookup fails loudly on a name the library never mentions.
atom(Name) ->
    _ = code:ensure_loaded(vpndetection_oauth),
    binary_to_existing_atom(Name).
