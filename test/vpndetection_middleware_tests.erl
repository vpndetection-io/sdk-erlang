%% The middleware half of the shared conformance corpus, which every framework
%% middleware in every language asserts, plus the Erlang-specific parts of it.
%%
%% The framework-shaped half - a Cowboy middleware, the request view it builds -
%% is asserted in the adapter against a real server. What is here is everything
%% a framework cannot change.
-module(vpndetection_middleware_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PUBLIC_IP, <<"45.83.91.1">>).

%%% ---------------------------------------------------------------- the corpus

corpus_conditions_test_() ->
    [{binary_to_list(Name), fun() -> assert_condition(Case) end}
     || #{<<"name">> := Name} = Case <- corpus(<<"conditions">>)].

assert_condition(#{<<"condition">> := Condition, <<"expect">> := Expect, <<"why">> := Why} = Case) ->
    {Ip, Routes} = fixture(Case),
    Stub = vpndetection_stub:start(Routes),
    Warnings = collector(),
    {ok, Core} = vpndetection_middleware:new(#{
        client => vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false,
                                     retries => 0}),
        ip_selector => fun(_View) -> Ip end,
        block_condition => Condition,
        on_warn => sink(Warnings)
    }),

    {ok, Found} = vpndetection_middleware:evaluate(Core, view(undefined, #{})),

    ?assertEqual({maps:get(<<"blocked">>, Expect), Why}, {maps:get(blocked, Found), Why}),
    Missing = maps:get(<<"missing">>, Expect, []),
    Reported = [W || W <- seen(Warnings), binary:match(W, <<"does not include">>) =/= nomatch],
    ?assertEqual({min(length(Missing), 1), Why}, {length(Reported), Why}),
    [?assertNotEqual({M, nomatch}, {M, binary:match(hd(Reported), M)}) || M <- Missing],
    vpndetection_stub:stop(Stub).

corpus_refuses_a_condition_that_constrains_nothing_test_() ->
    [{binary_to_list(Name),
      ?_assertMatch(
          {error, {constrains_nothing, _, _}},
          vpndetection_middleware:new(#{block_condition => Condition}))}
     || #{<<"name">> := Name, <<"condition">> := Condition} <- corpus(<<"invalidConditions">>)].

%%% --------------------------------------------------- what a framework cannot

enriches_without_blocking_when_no_condition_is_configured_test() ->
    {Stub, Core} = serving(#{<<"is_vpn">> => true}, #{ip_selector => fixed(?PUBLIC_IP)}),

    {ok, Found} = vpndetection_middleware:evaluate(Core, view(undefined, #{})),

    ?assertEqual(false, maps:get(blocked, Found)),
    ?assertEqual(?PUBLIC_IP, maps:get(ip, Found)),
    ?assertEqual(true, maps:get(is_vpn, maps:get(result, Found))),
    vpndetection_stub:stop(Stub).

a_condition_reaches_the_evidence_fields_test() ->
    {Stub, Other} = serving(
        #{<<"is_vpn">> => true, <<"vpn">> => #{<<"provider">> => <<"MULLVAD">>}},
        #{ip_selector => fixed(?PUBLIC_IP),
          block_condition => #{vpn => #{provider => <<"nordvpn">>}}}
    ),
    {ok, Missed} = vpndetection_middleware:evaluate(Other, view(undefined, #{})),
    ?assertEqual(false, maps:get(blocked, Missed)),
    vpndetection_stub:stop(Stub),

    {Stub2, Cased} = serving(
        #{<<"is_vpn">> => true, <<"vpn">> => #{<<"provider">> => <<"MULLVAD">>}},
        #{ip_selector => fixed(?PUBLIC_IP),
          block_condition => #{vpn => #{provider => <<"mullvad">>}}}
    ),
    {ok, Hit} = vpndetection_middleware:evaluate(Cased, view(undefined, #{})),
    ?assertEqual(true, maps:get(blocked, Hit)),
    vpndetection_stub:stop(Stub2).

fails_open_on_a_lookup_error_and_closed_only_when_asked_test() ->
    Routes = #{?PUBLIC_IP => #{status => 500, body => #{<<"error">> => <<"boom">>}}},

    Stub = vpndetection_stub:start(Routes),
    {ok, Opened} = core(Stub, #{ip_selector => fixed(?PUBLIC_IP),
                                block_condition => #{is_vpn => true}}),
    {ok, Found} = vpndetection_middleware:evaluate(Opened, view(undefined, #{})),
    ?assertEqual(false, maps:get(blocked, Found)),
    ?assertMatch(#{kind := server_error}, maps:get(error, Found)),
    ?assertEqual(undefined, maps:get(result, Found)),

    {ok, Closed} = core(Stub, #{ip_selector => fixed(?PUBLIC_IP),
                                block_condition => #{is_vpn => true},
                                fail_closed => true}),
    {ok, Blocked} = vpndetection_middleware:evaluate(Closed, view(undefined, #{})),
    ?assertEqual(true, maps:get(blocked, Blocked)),
    vpndetection_stub:stop(Stub).

a_private_client_address_warns_once_and_never_reaches_the_network_test() ->
    Stub = vpndetection_stub:start(#{}),
    Warnings = collector(),
    {ok, Core} = core(Stub, #{ip_selector => fixed(<<"10.0.0.7">>),
                              block_condition => #{is_vpn => true},
                              on_warn => sink(Warnings)}),

    [begin
         {ok, Found} = vpndetection_middleware:evaluate(Core, view(undefined, #{})),
         ?assertEqual(false, maps:get(blocked, Found)),
         ?assertEqual(true, maps:get(is_bogon, maps:get(result, Found)))
     end || _ <- [1, 2]],

    ?assertEqual(0, vpndetection_stub:calls(Stub)),
    ?assertMatch([_], seen(Warnings)),
    ?assertNotEqual(nomatch, binary:match(hd(seen(Warnings)), <<"not a public address">>)),
    vpndetection_stub:stop(Stub).

a_missing_member_warns_once_or_fails_on_request_test() ->
    Warnings = collector(),
    {Stub, Warned} = serving(#{<<"is_vpn">> => true},
                             #{ip_selector => fixed(?PUBLIC_IP),
                               block_condition => #{is_hosting => true},
                               on_warn => sink(Warnings)}),
    [vpndetection_middleware:evaluate(Warned, view(undefined, #{})) || _ <- [1, 2]],
    ?assertMatch([_], seen(Warnings)),
    ?assertNotEqual(nomatch, binary:match(hd(seen(Warnings)), <<"is_hosting">>)),

    {ok, Strict} = core(Stub, #{ip_selector => fixed(?PUBLIC_IP),
                                block_condition => #{is_hosting => true},
                                on_missing_field => error}),
    ?assertMatch({error, {missing_members, [<<"is_hosting">>], _}},
                 vpndetection_middleware:evaluate(Strict, view(undefined, #{}))),
    vpndetection_stub:stop(Stub).

an_unresolvable_address_warns_and_does_not_block_test() ->
    Stub = vpndetection_stub:start(#{}),
    Warnings = collector(),
    {ok, Core} = core(Stub, #{block_condition => #{is_vpn => true},
                              on_warn => sink(Warnings)}),

    {ok, Found} = vpndetection_middleware:evaluate(Core, view(undefined, #{})),

    ?assertEqual(false, maps:get(blocked, Found)),
    ?assertMatch(#{kind := bad_request}, maps:get(error, Found)),
    ?assertNotEqual(nomatch, binary:match(hd(seen(Warnings)),
                                          <<"could not resolve a client address">>)),
    vpndetection_stub:stop(Stub).

selectors_read_what_they_say_they_read_test() ->
    Chained = view(<<"10.0.0.1">>,
                   #{<<"x-forwarded-for">> => <<"203.0.113.9, 70.41.3.18, 150.172.238.178">>}),

    ?assertEqual(<<"10.0.0.1">>, run(vpndetection_selectors:framework_ip(), Chained)),
    ?assertEqual(<<"203.0.113.9">>, run(vpndetection_selectors:xff(0), Chained)),
    ?assertEqual(<<"150.172.238.178">>, run(vpndetection_selectors:xff(1), Chained)),
    ?assertEqual(<<"70.41.3.18">>, run(vpndetection_selectors:xff(2), Chained)),
    %% Past the chain's length the depth is meaningless, so this falls back to
    %% the left-most rather than indexing off the end.
    ?assertEqual(<<"203.0.113.9">>, run(vpndetection_selectors:xff(9), Chained)),
    ?assertEqual(<<"10.0.0.1">>, run(vpndetection_selectors:header(<<"CF-Connecting-IP">>),
                                     Chained)),

    Cloudflared = view(<<"10.0.0.1">>, #{<<"cf-connecting-ip">> => <<"198.51.100.4">>}),
    ?assertEqual(<<"198.51.100.4">>,
                 run(vpndetection_selectors:header(<<"CF-Connecting-IP">>), Cloudflared)),
    ?assertEqual(<<"10.0.0.1">>,
                 run(vpndetection_selectors:xff(0), view(<<"10.0.0.1">>, #{}))).

%% A condition decoded from JSON carries binary keys and binary values, which is
%% the shape an app whose policy lives in config gets for free.
a_condition_from_json_reads_the_same_as_one_written_in_erlang_test() ->
    Decoded = json:decode(<<"{\"is_vpn\":true,\"vpn\":{\"confidence\":[\"high\",\"medium\"]}}">>),
    {Stub, _} = serving(#{}, #{}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),
    Result = vpndetection_result:from_wire(
        #{<<"ip">> => ?PUBLIC_IP, <<"is_vpn">> => true,
          <<"vpn">> => #{<<"confidence">> => <<"HIGH">>}}),

    ?assert(vpndetection_condition:matches(Decoded, Result)),
    ?assert(vpndetection_condition:matches(
        #{is_vpn => true, vpn => #{confidence => [<<"high">>, <<"medium">>]}}, Result)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%%% ------------------------------------------------------------------- helpers

fixture(#{<<"bogon">> := Ip}) ->
    %% Answered locally, so this needs no route and pins the synthesized shape
    %% rather than a fixture's idea of it.
    {Ip, #{}};
fixture(#{<<"body">> := Body}) ->
    Ip = maps:get(<<"ip">>, Body),
    {Ip, #{Ip => #{status => 200, body => Body}}}.

serving(Body, Options) ->
    Stub = vpndetection_stub:start(
        #{?PUBLIC_IP => #{status => 200, body => Body#{<<"ip">> => ?PUBLIC_IP}}}
    ),
    {ok, Core} = core(Stub, Options),
    {Stub, Core}.

core(Stub, Options) ->
    vpndetection_middleware:new(Options#{
        client => vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false,
                                     retries => 0})
    }).

fixed(Ip) ->
    fun(_View) -> Ip end.

view(Ip, Headers) ->
    #{header => fun(Name) -> maps:get(string:lowercase(Name), Headers, undefined) end,
      framework_ip => fun() -> Ip end}.

run(Selector, View) ->
    vpndetection_selectors:resolve(Selector, View).

%% eunit runs each test in its own process, so a plain ref-counted collector
%% process is enough and needs no cleanup beyond the test's own lifetime.
collector() ->
    spawn_link(fun() -> collect([]) end).

collect(Seen) ->
    receive
        {warn, Message} -> collect(Seen ++ [Message]);
        {seen, From} ->
            From ! {seen, Seen},
            collect(Seen)
    end.

sink(Pid) ->
    fun(Message) -> Pid ! {warn, Message} end.

seen(Pid) ->
    Pid ! {seen, self()},
    receive
        {seen, Messages} -> Messages
    after 5000 -> erlang:error(timeout)
    end.

corpus(Section) ->
    {ok, Raw} = file:read_file(testdata_path()),
    maps:get(Section, maps:get(<<"middleware">>, json:decode(Raw))).

%% rebar3 runs from the project root, but a bare eunit run from anywhere else
%% would not, so fall back to walking up from the built application.
testdata_path() ->
    case filelib:is_regular("testdata/testdata.json") of
        true ->
            "testdata/testdata.json";
        false ->
            filename:join([code:lib_dir(vpndetection), "..", "..", "..", "..",
                           "testdata", "testdata.json"])
    end.
