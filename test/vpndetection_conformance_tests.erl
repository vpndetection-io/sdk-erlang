%% Asserts the shared conformance corpus that every VPNDetection SDK asserts.
%%
%% The corpus is generated into testdata/ and is identical across languages, so a
%% behavior that drifts here fails here rather than surfacing as two client
%% libraries quietly disagreeing about the same address.
-module(vpndetection_conformance_tests).

-include_lib("eunit/include/eunit.hrl").

is_bogon_test_() ->
    [{binary_to_list(<<Ip/binary, " (", Why/binary, ")">>),
      ?_assertEqual(Expect, vpndetection:is_bogon(Ip))}
     || #{<<"ip">> := Ip, <<"expect">> := Expect, <<"why">> := Why} <- corpus(<<"isBogon">>)].

bogon_is_answered_locally_in_the_full_max_shape_test() ->
    Stub = vpndetection_stub:start(#{}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),
    {ok, Result} = vpndetection:lookup(Client, <<"10.0.0.1">>),

    ?assertEqual(true, maps:get(is_bogon, Result)),
    ?assertEqual(<<"10.0.0.1">>, maps:get(ip, Result)),
    #{<<"flagsFalse">> := Flags, <<"emptyObjects">> := Objects} = corpus(<<"bogonResponse">>),
    [?assertEqual({F, false}, {F, maps:get(atom(F), Result, missing)}) || F <- Flags],
    [?assertEqual({O, #{}}, {O, maps:get(atom(O), Result, missing)}) || O <- Objects],
    ?assertEqual(0, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

lookup_preserves_absent_versus_false_test_() ->
    [{binary_to_list(Name), fun() -> assert_shape(Case) end}
     || #{<<"name">> := Name} = Case <- corpus(<<"lookup">>)].

assert_shape(#{<<"body">> := Body, <<"status">> := Status, <<"expect">> := Expect}) ->
    Ip = maps:get(<<"ip">>, Body),
    Stub = vpndetection_stub:start(#{Ip => #{status => Status, body => Body}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),
    {ok, Result} = vpndetection:lookup(Client, Ip),

    ?assertEqual(maps:get(<<"ip">>, Expect), maps:get(ip, Result)),
    ?assertEqual(maps:get(<<"isBogon">>, Expect), maps:get(is_bogon, Result)),
    maps:foreach(fun(K, V) ->
        ?assertEqual({K, V}, {K, maps:get(atom(K), Result, missing)})
    end, maps:get(<<"present">>, Expect, #{})),
    %% The whole point of the corpus: a plan-gated member the server did not send
    %% must be ABSENT, which is a different answer from present-and-false.
    [?assertEqual({K, error}, {K, maps:find(atom(K), Result)})
     || K <- maps:get(<<"absent">>, Expect, [])],
    [?assertEqual({K, #{}}, {K, maps:get(atom(K), Result, missing)})
     || K <- maps:get(<<"emptyPresent">>, Expect, [])],
    [assert_detail(Obj, Expect, Result) || Obj <- [<<"vpn">>, <<"hosting">>, <<"dcproxy">>]],
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

assert_detail(Obj, Expect, Result) ->
    case maps:find(Obj, Expect) of
        {ok, Detail} ->
            Got = maps:get(atom(Obj), Result, missing),
            maps:foreach(fun(K, V) ->
                ?assertEqual({Obj, K, V}, {Obj, K, maps:get(atom(K), Got, missing)})
            end, Detail),
            ?assertEqual({Obj, map_size(Detail)}, {Obj, map_size(Got)});
        error ->
            ok
    end.

errors_are_classified_by_range_and_by_retry_after_test_() ->
    [{binary_to_list(Name), fun() -> assert_error(Case) end}
     || #{<<"name">> := Name} = Case <- corpus(<<"errors">>)].

assert_error(#{<<"status">> := Status, <<"headers">> := Headers, <<"body">> := Body,
               <<"expect">> := Expect}) ->
    Stub = vpndetection_stub:start(#{<<"1.1.1.1">> => #{status => Status, body => Body,
                                                        headers => Headers}}),
    %% No retries, so a retryable failure still surfaces rather than looping.
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), retries => 0}),
    {error, Error} = vpndetection:lookup(Client, <<"1.1.1.1">>),

    ?assertEqual(atom(maps:get(<<"kind">>, Expect)), maps:get(kind, Error)),
    ?assertEqual(maps:get(<<"retryable">>, Expect), maps:get(retryable, Error)),
    case maps:find(<<"message">>, Expect) of
        {ok, Message} -> ?assertEqual(Message, maps:get(message, Error));
        error -> ok
    end,
    case maps:find(<<"retryAfterSeconds">>, Expect) of
        {ok, Seconds} -> ?assertEqual(Seconds, maps:get(retry_after, Error));
        error -> ok
    end,
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

batch_dedupes_short_circuits_bogons_and_keys_by_address_test() ->
    Expect = batch_expect(<<"dedup-bogon-and-order-free-keying">>),
    Stub = vpndetection_stub:start(#{
        <<"1.1.1.1">> => #{body => #{<<"ip">> => <<"1.1.1.1">>, <<"is_vpn">> => false}},
        <<"8.8.8.8">> => #{body => #{<<"ip">> => <<"8.8.8.8">>, <<"is_vpn">> => false}}
    }),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),
    Got = vpndetection:lookup_batch(Client, batch_input(<<"dedup-bogon-and-order-free-keying">>)),

    %% Erlang maps carry no insertion order, so the claim is the KEY SET: the
    %% deduplicated input, whatever order it was supplied in.
    ?assertEqual(lists:sort(maps:get(<<"keys">>, Expect)), lists:sort(maps:keys(Got))),
    ?assertEqual(maps:get(<<"httpRequests">>, Expect), vpndetection_stub:calls(Stub)),
    [?assertMatch({ok, #{is_bogon := true}}, maps:get(K, Got))
     || K <- maps:get(<<"bogonKeys">>, Expect)],
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

one_bad_address_does_not_lose_the_rest_of_the_batch_test() ->
    Expect = batch_expect(<<"partial-failure-does-not-fail-the-batch">>),
    Stub = vpndetection_stub:start(#{
        <<"1.1.1.1">> => #{body => #{<<"ip">> => <<"1.1.1.1">>, <<"is_vpn">> => false}}
    }),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), retries => 0}),
    Got = vpndetection:lookup_batch(Client, batch_input(<<"partial-failure-does-not-fail-the-batch">>)),

    ?assertEqual(lists:sort(maps:get(<<"keys">>, Expect)), lists:sort(maps:keys(Got))),
    Kinds = maps:get(<<"errorKinds">>, Expect),
    [begin
         {error, #{kind := Kind}} = maps:get(K, Got),
         ?assertEqual(binary_to_atom(maps:get(K, Kinds)), Kind)
     end || K <- maps:get(<<"errorKeys">>, Expect)],
    ?assertMatch({ok, #{is_vpn := false}}, maps:get(<<"1.1.1.1">>, Got)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

cache_hit_issues_no_second_request_test() ->
    Name = <<"cache-hit-issues-no-second-request">>,
    Case = case_of(<<"batch">>, Name),
    Expect = maps:get(<<"expect">>, Case),
    Stub = vpndetection_stub:start(#{
        <<"1.1.1.1">> => #{body => #{<<"ip">> => <<"1.1.1.1">>, <<"is_vpn">> => false}}
    }),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),
    Input = maps:get(<<"input">>, Case),
    [vpndetection:lookup_batch(Client, Input)
     || _ <- lists:seq(1, maps:get(<<"repeat">>, Case))],

    ?assertEqual(maps:get(<<"httpRequests">>, Expect), vpndetection_stub:calls(Stub)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

a_large_batch_is_sent_in_chunks_of_a_thousand_test() ->
    Name = <<"chunks-of-one-thousand">>,
    Input = batch_input(Name),
    Expect = batch_expect(Name),
    Stub = vpndetection_stub:start(maps:from_list(
        [{Ip, #{body => #{<<"ip">> => Ip, <<"is_vpn">> => false}}} || Ip <- Input])),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),
    Got = vpndetection:lookup_batch(Client, Input),

    ?assertEqual(maps:get(<<"keyCount">>, Expect), map_size(Got)),
    ?assertEqual(maps:get(<<"httpRequests">>, Expect), vpndetection_stub:calls(Stub)),
    [?assertMatch({ok, #{ip := Ip}}, maps:get(Ip, Got)) || Ip <- Input],
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%% No cap on what one call takes: the chunking is the client's job.
an_uncapped_batch_is_chunked_rather_than_refused_test() ->
    Name = <<"uncapped-input-is-chunked">>,
    Input = batch_input(Name),
    Expect = batch_expect(Name),
    Stub = vpndetection_stub:start(maps:from_list(
        [{Ip, #{body => #{<<"ip">> => Ip, <<"is_vpn">> => false}}} || Ip <- Input])),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),
    Got = vpndetection:lookup_batch(Client, Input),

    ?assertEqual(maps:get(<<"httpRequests">>, Expect), vpndetection_stub:calls(Stub)),
    ?assertEqual(maps:get(<<"keyCount">>, Expect), map_size(Got)),
    [?assertMatch({ok, #{ip := Ip}}, maps:get(Ip, Got)) || Ip <- Input],
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%% A per-entry failure carries no headers, so its 429 can only be a spent
%% allowance, and a 500 is the server's; neither is retried per entry, because
%% retries belong to the call and the call succeeded.
an_entry_error_is_classified_by_its_status_test() ->
    Name = <<"an-entry-error-is-classified-by-its-status">>,
    Expect = batch_expect(Name),
    Stub = vpndetection_stub:start(#{
        <<"1.1.1.1">> => #{body => #{<<"ip">> => <<"1.1.1.1">>, <<"is_vpn">> => false}},
        <<"8.8.8.8">> => #{status => 429,
                           body => #{<<"error">> => <<"request allowance exceeded; raise or remove your overage limit">>}},
        <<"9.9.9.9">> => #{status => 500, body => #{<<"error">> => <<"lookup failed">>}}
    }),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), retries => 3}),
    Got = vpndetection:lookup_batch(Client, batch_input(Name)),

    ?assertEqual(lists:sort(maps:get(<<"keys">>, Expect)), lists:sort(maps:keys(Got))),
    [begin
         {error, #{kind := Kind}} = maps:get(K, Got),
         ?assertEqual(binary_to_atom(V), Kind)
     end || {K, V} <- maps:to_list(maps:get(<<"errorKinds">>, Expect))],
    ?assertEqual(maps:get(<<"httpRequests">>, Expect), vpndetection_stub:calls(Stub)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

corpus(Key) ->
    maps:get(Key, testdata()).

testdata() ->
    {ok, Raw} = file:read_file(testdata_path()),
    json:decode(Raw).

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

case_of(Section, Name) ->
    [Case] = [C || #{<<"name">> := N} = C <- corpus(Section), N =:= Name],
    Case.

batch_expect(Name) ->
    maps:get(<<"expect">>, case_of(<<"batch">>, Name)).

batch_input(Name) ->
    maps:get(<<"input">>, case_of(<<"batch">>, Name)).

%% The corpus names fields the way the wire does. Turning one into the atom the
%% result map uses is an existing-atom lookup on purpose: a corpus key the
%% library never mentions must fail loudly rather than quietly assert that an
%% absent member is absent. Loading is forced because an atom only exists once
%% the module carrying it as a literal has been loaded.
atom(Name) ->
    _ = code:ensure_loaded(vpndetection_result),
    _ = code:ensure_loaded(vpndetection_error),
    binary_to_existing_atom(Name).
