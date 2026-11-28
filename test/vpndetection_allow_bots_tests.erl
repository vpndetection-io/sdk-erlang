%% `allow_bots', from a public peer: a crawler's own User-Agent reaches the
%% origin with its lookup, at most four an address, a crawler its operator vouches
%% for passes a condition it otherwise meets, a spoofed or not_bot one does not,
%% and off sends no agent. A bogon peer would be answered locally and pass
%% vacuously, so the peer here is public, bar the one test of what a bogon is not.
-module(vpndetection_allow_bots_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PUBLIC_IP, <<"66.249.66.1">>).
-define(GOOGLEBOT, <<"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)">>).
-define(SPOOFED, <<"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)">>).
%% A crawler's agent the stub answers `not_bot'.
-define(OTHER_BOT, <<"Mozilla/5.0 (compatible; Examplebot/1.0)">>).
-define(CHROME, <<"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/151.0.0.0 Safari/537.36">>).
-define(VPN, #{is_vpn => true}).
-define(IS_BOT, #{is_bot => true}).

%% On, a crawler's own agent and only it reaches the origin: an absent or blank
%% header sends none, and off sends none whatever the request carried.
the_requests_own_agent_reaches_the_origin_test() ->
    {Core, Seen, Warnings} = core(#{allow_bots => true, block_condition => ?VPN}),
    {ok, Found} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    ?assertEqual([?GOOGLEBOT], agents(Seen)),
    ?assertMatch(#{blocked := false, result := #{user_agent := #{verdict := <<"verified">>}}}, Found),
    {ok, Absent} = vpndetection_middleware:evaluate(Core, view(#{})),
    {ok, Blank} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => <<"  ">>})),
    ?assertEqual([?GOOGLEBOT, none, none], agents(Seen)),
    ?assertEqual({true, true}, {maps:get(blocked, Absent), maps:get(blocked, Blank)}),
    ?assertEqual([], seen(Warnings)),

    {Off, OffSeen, _} = core(#{block_condition => ?VPN}),
    {ok, Refused} = vpndetection_middleware:evaluate(Off, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    ?assertEqual([none], agents(OffSeen)),
    ?assertEqual(true, maps:get(blocked, Refused)).

a_verified_crawler_passes_a_condition_it_otherwise_meets_test_() ->
    [{binary_to_list(Agent), fun() ->
        {Core, Seen, _} = core(#{allow_bots => true, block_condition => ?VPN}),
        {ok, Found} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => Agent})),
        ?assertEqual([Agent], agents(Seen)),
        ?assertEqual({Verdict, Blocked}, {Verdict, maps:get(blocked, Found)}),
        %% The answer is attached either way.
        ?assertMatch(#{result := #{is_vpn := true, user_agent := #{verdict := Verdict}}}, Found)
     end} || {Agent, Verdict, Blocked} <- [{?GOOGLEBOT, <<"verified">>, false},
                                           {?SPOOFED, <<"spoofed">>, true},
                                           {?OTHER_BOT, <<"not_bot">>, true}]].

%% A guard written to refuse a forged crawler matches only with it on, and never
%% refuses a verified one.
a_condition_on_the_verdict_refuses_a_spoofed_crawler_test() ->
    Condition = #{user_agent => #{verdict => <<"spoofed">>}},
    {Core, _, _} = core(#{allow_bots => true, block_condition => Condition}),
    {ok, Spoofed} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?SPOOFED})),
    {ok, Verified} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    ?assertEqual(true, maps:get(blocked, Spoofed)),
    ?assertEqual(false, maps:get(blocked, Verified)).

%% A keyless client, or a free key past its trial, is never answered a verdict:
%% nothing is let through, and `on_missing_field' says so once, or fails the
%% request when set to `error'.
a_served_answer_with_no_verdict_is_reported_once_test() ->
    {Core, Seen, Warnings} = core(#{allow_bots => true, block_condition => ?VPN}, no_verdicts),
    {ok, First} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    {ok, _} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?OTHER_BOT})),
    ?assertEqual([?GOOGLEBOT, ?OTHER_BOT], agents(Seen)),
    ?assertEqual(true, maps:get(blocked, First)),
    ?assertMatch([_], [W || W <- seen(Warnings), binary:match(W, <<"user_agent">>) =/= nomatch]),

    {Strict, _, _} = core(#{allow_bots => true, on_missing_field => error}, no_verdicts),
    ?assertMatch({error, {missing_members, [<<"user_agent">>], _}},
                 vpndetection_middleware:evaluate(Strict, view(#{<<"user-agent">> => ?GOOGLEBOT}))),
    {Quiet, _, QuietWarnings} = core(#{allow_bots => true, on_missing_field => ignore}, no_verdicts),
    {ok, _} = vpndetection_middleware:evaluate(Quiet, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    ?assertEqual([], seen(QuietWarnings)).

%% The corpus says which agents name a crawler, and an agent that names none
%% stays off the lookup, so an address costs one lookup whatever browsers it
%% arrives with.
only_an_agent_naming_a_crawler_is_sent_as_the_corpus_says_test() ->
    #{<<"terms">> := Terms, <<"crawlers">> := Crawlers, <<"others">> := Others} = corpus(<<"crawlerAgents">>),
    ?assert(Crawlers =/= [] andalso Others =/= []),
    [?assertEqual({Agent, true}, {Agent, vpndetection_middleware:names_crawler(Agent)}) || Agent <- Crawlers],
    [?assertEqual({Agent, false}, {Agent, vpndetection_middleware:names_crawler(Agent)}) || Agent <- Others],
    [?assertEqual({Term, true},
                  {Term, vpndetection_middleware:names_crawler(<<"x ", (string:uppercase(Term))/binary, " y">>)})
     || Term <- Terms],
    {Core, Seen, _} = core(#{allow_bots => true, block_condition => ?IS_BOT}),
    {ok, Found} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?CHROME})),
    ?assertEqual([none], agents(Seen)),
    ?assertEqual(true, maps:get(blocked, Found)).

%% Only `A' to `Z' are lowercased: the Kelvin sign is a `k' to Unicode, and an agent
%% that names a crawler only through it names none.
the_lowercasing_is_ascii_only_test() ->
    ?assertEqual(true, vpndetection_middleware:names_crawler(<<"x BARKROWLER y">>)),
    ?assertEqual(false, vpndetection_middleware:names_crawler(<<"x BAR", 16#212A/utf8, "ROWLER y">>)).

%% A visitor inventing an agent a request spends at most four lookups, and what
%% is past them is judged by the condition alone: a stub that answers `verified'
%% to any agent never gets the chance.
one_address_is_looked_up_with_at_most_four_crawler_agents_test() ->
    ?assertEqual(4, vpndetection_middleware:max_agents_per_address()),
    {Core, Seen, Warnings} = core(#{allow_bots => true, block_condition => ?IS_BOT}, verified_any),
    [?assertMatch(#{blocked := false}, found(Core, crawler(N))) || N <- [1, 2, 3, 4]],
    #{blocked := Blocked, result := Result} = found(Core, crawler(5)),
    ?assertEqual(true, Blocked),
    ?assertEqual(false, maps:is_key(user_agent, Result)),
    ?assertMatch(#{blocked := false}, found(Core, crawler(1))),
    ?assertEqual([crawler(1), crawler(2), crawler(3), crawler(4), none, crawler(1)], agents(Seen)),
    ?assertEqual([], seen(Warnings)),

    ?assertMatch(#{blocked := false}, found(Core, crawler(5), <<"66.249.66.2">>)),
    ?assertEqual(crawler(5), lists:last(agents(Seen))).

%% An address its operator vouches for passes as a crawler past the bound too.
past_the_bound_an_address_its_operator_vouches_for_still_passes_test() ->
    {Core, Seen, _} = core(#{allow_bots => true, block_condition => ?IS_BOT},
                           {verified_any, #{<<"verified">> => true}}),
    [?assertMatch(#{blocked := false}, found(Core, crawler(N))) || N <- [1, 2, 3, 4, 5]],
    ?assertEqual(none, lists:last(agents(Seen))),
    ?assertMatch(#{blocked := true}, found(Core, ?CHROME)).

%% A request that sent no agent (a browser's, none at all, or one past its address's
%% bound) has no verdict to lack, whatever the plan serves: a condition on the
%% verdict is no plan gap there, so `on_missing_field' set to `error' fails nothing.
%% Off, such a condition can never match, and is still reported.
a_condition_on_the_verdict_is_no_plan_gap_for_a_request_that_sent_no_agent_test() ->
    Forged = #{user_agent => #{verdict => <<"spoofed">>}},
    Options = #{allow_bots => true, block_condition => Forged, on_missing_field => error},
    [begin
        {Core, Seen, Warnings} = core(Options),
        ?assertMatch({ok, #{blocked := false}}, vpndetection_middleware:evaluate(Core, view(Headers))),
        ?assertEqual([none], agents(Seen)),
        ?assertEqual([], seen(Warnings))
     end || Headers <- [#{<<"user-agent">> => ?CHROME}, #{}]],
    {Core, Seen, Warnings} = core(Options),
    [?assertMatch(#{blocked := false}, found(Core, crawler(N))) || N <- [1, 2, 3, 4]],
    ?assertMatch(#{blocked := false}, found(Core, crawler(5))),
    ?assertEqual(none, lists:last(agents(Seen))),
    ?assertEqual([], seen(Warnings)),

    {Off, _, OffWarnings} = core(#{block_condition => Forged}),
    {ok, _} = vpndetection_middleware:evaluate(Off, view(#{})),
    ?assertMatch([_], [W || W <- seen(OffWarnings), binary:match(W, <<"user_agent">>) =/= nomatch]).

%% A bogon peer, local development behind no proxy, is answered locally in the widest
%% shape and carries no verdict, and that is no plan gap: `on_missing_field' set to
%% `error' answered a crawler's request there with an error, and `warn' said the plan
%% lacked `user_agent'. The origin would answer `spoofed' to any agent, so a request
%% that reached it would be refused.
a_bogon_peer_with_a_crawler_agent_is_no_plan_gap_test_() ->
    Forged = #{user_agent => #{verdict => <<"spoofed">>}},
    [{lists:flatten(io_lib:format("~s, ~s", [Peer, Action])), fun() ->
        {Core, Seen, Warnings} = core(#{allow_bots => true, block_condition => Forged,
                                        on_missing_field => Action}, spoofed_any),
        Evaluated = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?GOOGLEBOT}, Peer)),
        ?assertMatch({ok, #{blocked := false, ip := Peer, error := undefined,
                            result := #{is_bogon := true}}}, Evaluated),
        {ok, #{result := Result}} = Evaluated,
        ?assertEqual([], vpndetection_condition:missing_members(Forged, Result)),
        ?assertEqual([], [W || W <- seen(Warnings), binary:match(W, [<<"does not include">>, <<"user_agent">>]) =/= nomatch]),
        ?assertEqual([], agents(Seen))
     end} || Peer <- [<<"127.0.0.1">>, <<"10.0.0.1">>, <<"::1">>], Action <- [error, warn]].

%% Held an hour from an address's first agent, whatever is added after, and no
%% more than a bounded number of addresses.
a_cache_holds_claims_from_the_first_for_a_bounded_set_of_keys_test() ->
    {ok, Cache} = vpndetection_cache:start_link(2, 600),
    Claim = fun(Key, Item, Bound) -> vpndetection_cache:claim(Cache, Key, Item, Bound) end,
    ?assertEqual([sent, sent], [Claim(<<"a">>, <<"1">>, 2), Claim(<<"a">>, <<"1">>, 2)]),
    timer:sleep(300),
    ?assertEqual([sent, past, sent], [Claim(<<"a">>, <<"2">>, 2), Claim(<<"a">>, <<"3">>, 2), Claim(<<"a">>, <<"1">>, 2)]),
    timer:sleep(400),
    %% 700 ms after the first, past its 600: the second, added at 300, did not extend it.
    ?assertEqual([sent, sent, past],
                 [Claim(<<"a">>, <<"3">>, 2), Claim(<<"a">>, <<"4">>, 2), Claim(<<"a">>, <<"5">>, 2)]),
    %% Two keys held: a third forgets the least recently used, which starts afresh.
    ?assertEqual([sent, sent], [Claim(K, <<"1">>, 1) || K <- [<<"b">>, <<"c">>]]),
    ?assertEqual(past, Claim(<<"c">>, <<"2">>, 1)),
    ?assertEqual(sent, Claim(<<"a">>, <<"1">>, 1)),
    ?assertEqual(sent, Claim(<<"b">>, <<"2">>, 1)),
    vpndetection_cache:stop(Cache).

%% What a core remembers goes with it.
closing_a_core_stops_what_it_remembers_test() ->
    {Core, _, _} = core(#{allow_bots => true}),
    #{agents := #{pid := Pid}} = Core,
    ?assert(is_process_alive(Pid)),
    ok = vpndetection_middleware:close(Core),
    ?assertNot(is_process_alive(Pid)),
    {Off, _, _} = core(#{}),
    ?assertMatch(#{agents := undefined}, Off).

%%% ------------------------------------------------------------------ helpers

crawler(N) ->
    iolist_to_binary(io_lib:format("Mozilla/5.0 (compatible; Examplebot/~b.0)", [N])).

found(Core, Agent) ->
    found(Core, Agent, ?PUBLIC_IP).

found(Core, Agent, Ip) ->
    {ok, Found} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => Agent}, Ip)),
    Found.

corpus(Section) ->
    {ok, Raw} = file:read_file("testdata/testdata.json"),
    maps:get(Section, json:decode(Raw)).

core(Options) ->
    core(Options, verdicts).

%% A core over an origin that answers every address as a VPN and a bot, with the
%% verdict for the agent sent (none for `no_verdicts'; `verified' for any agent
%% under `verified_any', with the bot detail a `{verified_any, Bot}' adds, and
%% `spoofed' for any under `spoofed_any'),
%% recording each agent that arrived, `none' for a lookup that sent none.
core(Options, Verdicts) ->
    Recorder = spawn_link(fun() -> record([]) end),
    {Mode, Bot} = case Verdicts of
        {verified_any, Detail} -> {verified_any, Detail};
        _ -> {Verdicts, #{}}
    end,
    Http = fun(#{url := Url}) ->
        Parsed = uri_string:parse(Url),
        Query = uri_string:dissect_query(maps:get(query, Parsed, <<>>)),
        Agent = proplists:get_value(<<"user_agent">>, Query, none),
        Recorder ! {agent, Agent},
        Ip = lists:last(string:split(maps:get(path, Parsed), "/", all)),
        Answer = #{<<"ip">> => iolist_to_binary(Ip), <<"is_vpn">> => true, <<"is_bot">> => true,
                   <<"bot">> => Bot},
        Body = case {Mode, Agent} of
            {no_verdicts, _} -> Answer;
            {_, none} -> Answer;
            {verified_any, _} -> Answer#{<<"user_agent">> => verdict(<<"Examplebot">>, <<"bot">>, <<"verified">>)};
            {spoofed_any, _} -> Answer#{<<"user_agent">> => verdict(<<"Examplebot">>, <<"bot">>, <<"spoofed">>)};
            {_, ?GOOGLEBOT} -> Answer#{<<"user_agent">> => verdict(<<"Googlebot">>, <<"bot">>, <<"verified">>)};
            {_, ?SPOOFED} -> Answer#{<<"user_agent">> => verdict(<<"Bingbot">>, <<"bot">>, <<"spoofed">>)};
            {_, _} -> Answer#{<<"user_agent">> => verdict(<<"Examplebot">>, <<"bot">>, <<"not_bot">>)}
        end,
        {ok, #{status => 200, headers => [], body => iolist_to_binary(json:encode(Body))}}
    end,
    Warnings = spawn_link(fun() -> record([]) end),
    {ok, Core} = vpndetection_middleware:new(Options#{
        client => vpndetection:new(#{api_key => <<"k">>, http => Http, retries => 0, cache => false}),
        on_warn => fun(Message) -> Warnings ! {agent, Message} end
    }),
    {Core, Recorder, Warnings}.

verdict(Agent, Kind, Verdict) ->
    #{<<"agent">> => Agent, <<"kind">> => Kind, <<"verdict">> => Verdict}.

%% A request from a public peer carrying exactly these headers.
view(Headers) ->
    view(Headers, ?PUBLIC_IP).

view(Headers, Ip) ->
    #{header => fun(Name) -> maps:get(string:lowercase(Name), Headers, undefined) end,
      framework_ip => fun() -> Ip end}.

record(Seen) ->
    receive
        {agent, Agent} -> record(Seen ++ [Agent]);
        {seen, From} -> From ! {seen, Seen}, record(Seen)
    end.

seen(Recorder) ->
    Recorder ! {seen, self()},
    receive {seen, Seen} -> Seen after 5000 -> erlang:error(timeout) end.

agents(Recorder) ->
    seen(Recorder).
