%% The user agent of the request being decided on: sent with a lookup, `my_ip'
%% and a batch entry, cached on the address and agent together, and surfaced on
%% the answer as `user_agent'.
-module(vpndetection_user_agent_tests).

-include_lib("eunit/include/eunit.hrl").

-define(GOOGLEBOT, <<"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)">>).
-define(IP, <<"66.249.66.1">>).

%% The agent reaches the origin as the query parameter, every reserved byte
%% percent-encoded and `+' as `%2B', so it cannot arrive as a space; the answer
%% hands its verdict back.
the_agent_reaches_the_origin_encoded_and_its_verdict_comes_back_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http, cache => false}),
    {ok, Result} = vpndetection:lookup(Client, ?IP, #{user_agent => ?GOOGLEBOT}),
    {ok, Mine} = vpndetection:my_ip(Client, #{user_agent => binary_to_list(?GOOGLEBOT)}),
    [Lookup, MyIp] = urls(Seen),
    Encoded = <<"user_agent=Mozilla%2F5.0%20%28compatible%3B%20Googlebot%2F2.1%3B%20"
                "%2Bhttp%3A%2F%2Fwww.google.com%2Fbot.html%29">>,
    ?assertEqual(<<"/66.249.66.1?", Encoded/binary>>, path_and_query(Lookup)),
    ?assertEqual(<<"/myip?", Encoded/binary>>, path_and_query(MyIp)),
    Verdict = #{agent => <<"Googlebot">>, kind => <<"bot">>, verdict => <<"verified">>},
    ?assertEqual(Verdict, maps:get(user_agent, Result)),
    ?assertEqual(Verdict, maps:get(user_agent, Mine)),
    vpndetection:close(Client).

%% No agent, or an empty one, sends no parameter and is answered no verdict.
an_empty_agent_is_none_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http, cache => false}),
    {ok, Plain} = vpndetection:lookup(Client, ?IP, #{user_agent => <<>>}),
    {ok, _} = vpndetection:lookup(Client, ?IP, #{user_agent => ""}),
    {ok, _} = vpndetection:my_ip(Client, #{user_agent => <<>>}),
    {ok, Sent} = vpndetection:lookup(Client, ?IP, #{user_agent => <<"curl/8">>}),
    ?assertEqual([<<"/66.249.66.1">>, <<"/66.249.66.1">>, <<"/myip">>, <<"/66.249.66.1?user_agent=curl%2F8">>],
                 [path_and_query(U) || U <- urls(Seen)]),
    ?assertNot(maps:is_key(user_agent, Plain)),
    ?assertMatch(#{user_agent := #{verdict := <<"not_bot">>}}, Sent).

%% One past the spec's 1024 characters is sent whole, never refused.
a_long_agent_is_sent_whole_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http, cache => false}),
    Long = binary:copy(<<"a">>, 2000),
    {ok, _} = vpndetection:lookup(Client, ?IP, #{user_agent => Long}),
    [Url] = urls(Seen),
    ?assertEqual([{<<"user_agent">>, Long}], query(Url)).

%% The answer with an agent is cached on the address and agent together: two
%% agents for one address are two requests, the same pair again is none, and
%% the plain answer is a third. `my_ip' stays uncached.
the_cache_keys_on_the_address_and_agent_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http}),
    {ok, A} = vpndetection:lookup(Client, ?IP, #{user_agent => ?GOOGLEBOT}),
    {ok, B} = vpndetection:lookup(Client, ?IP, #{user_agent => <<"curl/8">>}),
    {ok, A} = vpndetection:lookup(Client, ?IP, #{user_agent => ?GOOGLEBOT}),
    {ok, B} = vpndetection:lookup(Client, ?IP, #{user_agent => <<"curl/8">>}),
    {ok, Plain} = vpndetection:lookup(Client, ?IP),
    {ok, Plain} = vpndetection:lookup(Client, ?IP, #{user_agent => <<>>}),
    {ok, _} = vpndetection:my_ip(Client, #{user_agent => ?GOOGLEBOT}),
    {ok, _} = vpndetection:my_ip(Client, #{user_agent => ?GOOGLEBOT}),
    ?assertEqual(5, length(urls(Seen))),
    ?assertMatch(#{user_agent := #{verdict := <<"verified">>}}, A),
    ?assertMatch(#{user_agent := #{verdict := <<"not_bot">>}}, B),
    ?assertNot(maps:is_key(user_agent, Plain)),
    vpndetection:close(Client).

%% Concurrent misses for one address and agent share one request; another
%% agent for the same address is a request of its own.
concurrent_misses_for_one_pair_share_one_request_test() ->
    Gate = gate(),
    {Http, Seen} = origin(fun() -> held(Gate) end),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http}),
    Parent = self(),
    Ask = fun(Agent) ->
        spawn_link(fun() -> Parent ! {answered, Agent, vpndetection:lookup(Client, ?IP, #{user_agent => Agent})} end)
    end,
    [Ask(?GOOGLEBOT) || _ <- lists:seq(1, 6)],
    Ask(<<"curl/8">>),
    %% Every caller is in the air before the origin answers anyone.
    wait_until(fun() -> length(urls_so_far(Seen)) =:= 2 end),
    timer:sleep(200),
    Gate ! open,
    Answers = [receive {answered, Agent, Answer} -> {Agent, Answer} after 10000 -> timeout end
               || _ <- lists:seq(1, 7)],
    ?assertEqual(2, length(urls(Seen))),
    ?assertEqual(6, length([ok || {Agent, {ok, #{user_agent := #{verdict := <<"verified">>}}}} <- Answers,
                                  Agent =:= ?GOOGLEBOT])),
    ?assertMatch([_], [ok || {<<"curl/8">>, {ok, #{user_agent := #{verdict := <<"not_bot">>}}}} <- Answers]),
    vpndetection:close(Client).

%% A batch sends `user_agents' keyed by each address exactly as it goes in
%% `ips', an IPv4-mapped one by the IPv4 address it carries; a batch where no
%% address has one sends none, never `{}'. A bogon stays local, with no
%% `user_agent', and the cache keys a batch entry on the pair as a lookup does.
a_batch_sends_each_agent_keyed_as_the_address_is_sent_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http}),
    V6 = <<"2001:4860:4801:10::1">>,
    Answers = vpndetection:lookup_batch(Client, [?IP, <<"::ffff:8.8.8.8">>, V6, <<"1.1.1.1">>, <<"10.0.0.1">>],
                                        #{user_agents => #{?IP => ?GOOGLEBOT, "::ffff:8.8.8.8" => <<"curl/8">>,
                                                           V6 => <<"curl/8">>, <<"1.1.1.1">> => <<>>,
                                                           <<"10.0.0.1">> => ?GOOGLEBOT}}),
    [First] = bodies(Seen),
    ?assertEqual(#{?IP => ?GOOGLEBOT, <<"8.8.8.8">> => <<"curl/8">>, V6 => <<"curl/8">>},
                 maps:get(<<"user_agents">>, First)),
    ?assertEqual(lists:sort([?IP, <<"8.8.8.8">>, V6, <<"1.1.1.1">>]), lists:sort(maps:get(<<"ips">>, First))),
    ?assertMatch({ok, #{user_agent := #{verdict := <<"verified">>}}}, maps:get(?IP, Answers)),
    ?assertMatch({ok, #{user_agent := #{verdict := <<"not_bot">>}}}, maps:get(<<"::ffff:8.8.8.8">>, Answers)),
    {ok, Plain} = maps:get(<<"1.1.1.1">>, Answers),
    ?assertNot(maps:is_key(user_agent, Plain)),
    {ok, Bogon} = maps:get(<<"10.0.0.1">>, Answers),
    ?assertNot(maps:is_key(user_agent, Bogon)),
    ?assertNot(maps:is_key(<<"user_agent">>, maps:get(raw, Bogon))),

    %% The same pairs again are cached; the same addresses with no agent are not.
    _ = vpndetection:lookup_batch(Client, [?IP, V6], #{user_agents => #{?IP => ?GOOGLEBOT, V6 => <<"curl/8">>}}),
    ?assertEqual([], bodies(Seen)),
    _ = vpndetection:lookup_batch(Client, [?IP, V6]),
    [Second] = bodies(Seen),
    ?assertNot(maps:is_key(<<"user_agents">>, Second)),
    ?assertEqual(lists:sort([?IP, V6]), lists:sort(maps:get(<<"ips">>, Second))),
    vpndetection:close(Client).

%% A bogon is answered locally whatever agent is sent with it, with no verdict,
%% while the same client's public lookup carries one.
a_bogon_is_answered_locally_with_no_user_agent_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http}),
    {ok, Bogon} = vpndetection:lookup(Client, <<"10.0.0.1">>, #{user_agent => ?GOOGLEBOT}),
    ?assertEqual([], urls(Seen)),
    ?assertNot(maps:is_key(user_agent, Bogon)),
    ?assertNot(maps:is_key(<<"user_agent">>, maps:get(raw, Bogon))),
    {ok, Served} = vpndetection:lookup(Client, ?IP, #{user_agent => ?GOOGLEBOT}),
    ?assertMatch(#{user_agent := #{verdict := <<"verified">>}}, Served),
    vpndetection:close(Client).

%% An agent that is no text is the caller's mistake, refused before any request.
an_agent_that_is_no_text_is_refused_before_any_request_test() ->
    {Http, Seen} = origin(),
    Client = vpndetection:new(#{api_key => <<"k">>, http => Http, cache => false}),
    ?assertMatch({error, #{kind := bad_request}}, vpndetection:lookup(Client, ?IP, #{user_agent => 7})),
    ?assertMatch({error, #{kind := bad_request}}, vpndetection:my_ip(Client, #{user_agent => agent})),
    ?assertMatch(#{?IP := {error, #{kind := bad_request}}},
                 vpndetection:lookup_batch(Client, [?IP], #{user_agents => #{?IP => 7}})),
    ?assertMatch(#{?IP := {error, #{kind := bad_request}}},
                 vpndetection:lookup_batch(Client, [?IP], #{user_agents => [?IP]})),
    ?assertEqual([], urls(Seen)).

%%% ------------------------------------------------------------------ helpers

origin() ->
    origin(fun() -> ok end).

%% Answers a lookup, `my_ip' or a batch the way the API does: an agent sent
%% earns a verdict (`verified' for Googlebot's, `not_bot' for any other), and an
%% address sent with none earns none. Every request is recorded.
origin(Hold) ->
    Recorder = spawn_link(fun() -> record([]) end),
    Http = fun(#{url := Url} = Request) ->
        Body = maps:get(body, Request, <<>>),
        Recorder ! {request, Url, Body},
        Hold(),
        Answer = case Body of
            <<>> ->
                Agent = proplists:get_value(<<"user_agent">>, query(Url)),
                answer(path_ip(Url), Agent);
            _ ->
                Batch = json:decode(Body),
                Agents = maps:get(<<"user_agents">>, Batch, #{}),
                #{<<"results">> => maps:from_list([{Ip, answer(Ip, maps:get(Ip, Agents, undefined))}
                                                   || Ip <- maps:get(<<"ips">>, Batch)])}
        end,
        {ok, #{status => 200, headers => [], body => iolist_to_binary(json:encode(Answer))}}
    end,
    {Http, Recorder}.

answer(Ip, undefined) ->
    #{<<"ip">> => Ip, <<"is_vpn">> => false, <<"is_bot">> => true};
answer(Ip, Agent) ->
    Verdict = case Agent of
        ?GOOGLEBOT -> #{<<"agent">> => <<"Googlebot">>, <<"kind">> => <<"bot">>, <<"verdict">> => <<"verified">>};
        _ -> #{<<"agent">> => <<"curl">>, <<"kind">> => <<"http-client">>, <<"verdict">> => <<"not_bot">>}
    end,
    (answer(Ip, undefined))#{<<"user_agent">> => Verdict}.

path_ip(Url) ->
    case uri_string:percent_decode(maps:get(path, uri_string:parse(Url))) of
        <<"/myip">> -> ?IP;
        <<"/", Ip/binary>> -> Ip
    end.

record(Seen) ->
    receive
        {request, Url, Body} -> record(Seen ++ [{Url, Body}]);
        {take, From} -> From ! {seen, Seen}, record([]);
        {peek, From} -> From ! {seen, Seen}, record(Seen)
    end.

%% What reached the origin since the last take, in order.
taken(Recorder, How) ->
    Recorder ! {How, self()},
    receive {seen, Seen} -> Seen after 5000 -> erlang:error(timeout) end.

urls(Recorder) -> [Url || {Url, _} <- taken(Recorder, take)].
urls_so_far(Recorder) -> taken(Recorder, peek).
bodies(Recorder) -> [json:decode(Body) || {_, Body} <- taken(Recorder, take), Body =/= <<>>].

path_and_query(Url) ->
    #{path := Path} = Parsed = uri_string:parse(Url),
    case maps:find(query, Parsed) of
        {ok, Query} -> <<Path/binary, "?", Query/binary>>;
        error -> Path
    end.

query(Url) ->
    uri_string:dissect_query(maps:get(query, uri_string:parse(Url), <<>>)).

%% A gate the origin holds every request at until the test opens it.
gate() ->
    spawn_link(fun() -> closed([]) end).

closed(Waiting) ->
    receive
        {wait, From} -> closed([From | Waiting]);
        open -> [W ! go || W <- Waiting], opened()
    end.

opened() ->
    receive {wait, From} -> From ! go, opened() end.

held(Gate) ->
    Gate ! {wait, self()},
    receive go -> ok after 10000 -> erlang:error(gate_timeout) end.

wait_until(Check) ->
    wait_until(Check, 100).

wait_until(_Check, 0) ->
    erlang:error(never_happened);
wait_until(Check, N) ->
    case Check() of
        true -> ok;
        false -> timer:sleep(20), wait_until(Check, N - 1)
    end.
