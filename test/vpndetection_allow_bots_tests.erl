%% `allow_bots', from a public peer: the request's own User-Agent reaches the
%% origin with its lookup, a crawler its operator vouches for passes a condition
%% it otherwise meets, a spoofed or not_bot one does not, and off sends no agent.
%% A bogon peer would be answered locally and pass vacuously, so the peer here is
%% public.
-module(vpndetection_allow_bots_tests).

-include_lib("eunit/include/eunit.hrl").

-define(PUBLIC_IP, <<"66.249.66.1">>).
-define(GOOGLEBOT, <<"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)">>).
-define(SPOOFED, <<"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)">>).
-define(BROWSER, <<"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0">>).
-define(VPN, #{is_vpn => true}).

%% On, the request's own agent and only it reaches the origin: an absent or
%% blank header sends none, and off sends none whatever the request carried.
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
                                           {?BROWSER, <<"not_bot">>, true}]].

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
    {ok, _} = vpndetection_middleware:evaluate(Core, view(#{<<"user-agent">> => ?BROWSER})),
    ?assertEqual([?GOOGLEBOT, ?BROWSER], agents(Seen)),
    ?assertEqual(true, maps:get(blocked, First)),
    ?assertMatch([_], [W || W <- seen(Warnings), binary:match(W, <<"user_agent">>) =/= nomatch]),

    {Strict, _, _} = core(#{allow_bots => true, on_missing_field => error}, no_verdicts),
    ?assertMatch({error, {missing_members, [<<"user_agent">>], _}},
                 vpndetection_middleware:evaluate(Strict, view(#{<<"user-agent">> => ?GOOGLEBOT}))),
    {Quiet, _, QuietWarnings} = core(#{allow_bots => true, on_missing_field => ignore}, no_verdicts),
    {ok, _} = vpndetection_middleware:evaluate(Quiet, view(#{<<"user-agent">> => ?GOOGLEBOT})),
    ?assertEqual([], seen(QuietWarnings)).

%%% ------------------------------------------------------------------ helpers

core(Options) ->
    core(Options, verdicts).

%% A core over an origin that answers every address as a VPN, with the verdict
%% for the agent sent (none for `no_verdicts'), recording each agent that
%% arrived, `none' for a lookup that sent none.
core(Options, Verdicts) ->
    Recorder = spawn_link(fun() -> record([]) end),
    Http = fun(#{url := Url}) ->
        Query = uri_string:dissect_query(maps:get(query, uri_string:parse(Url), <<>>)),
        Agent = proplists:get_value(<<"user_agent">>, Query, none),
        Recorder ! {agent, Agent},
        Answer = #{<<"ip">> => ?PUBLIC_IP, <<"is_vpn">> => true},
        Body = case {Verdicts, Agent} of
            {no_verdicts, _} -> Answer;
            {_, none} -> Answer;
            {_, ?GOOGLEBOT} -> Answer#{<<"user_agent">> => verdict(<<"Googlebot">>, <<"bot">>, <<"verified">>)};
            {_, ?SPOOFED} -> Answer#{<<"user_agent">> => verdict(<<"Bingbot">>, <<"bot">>, <<"spoofed">>)};
            {_, _} -> Answer#{<<"user_agent">> => verdict(<<"Firefox">>, <<"browser">>, <<"not_bot">>)}
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
    #{header => fun(Name) -> maps:get(string:lowercase(Name), Headers, undefined) end,
      framework_ip => fun() -> ?PUBLIC_IP end}.

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
