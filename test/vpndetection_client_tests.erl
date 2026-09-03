%% The Erlang-specific API surface, as distinct from the shared conformance
%% corpus in vpndetection_conformance_tests.
-module(vpndetection_client_tests).

-include_lib("eunit/include/eunit.hrl").

-define(ADDRS, [<<"9.9.9.", (integer_to_binary(N))/binary>> || N <- lists:seq(1, 12)]).

is_bogon_is_on_the_client_and_agrees_with_the_standalone_export_test() ->
    Client = vpndetection:new(#{cache => false, http => fun(_) -> {error, unused} end}),
    [?assertEqual({Ip, vpndetection:is_bogon(Ip)}, {Ip, vpndetection:is_bogon(Client, Ip)})
     || Ip <- [<<"10.0.0.1">>, <<"8.8.8.8">>, <<"fe80::1">>, <<"2606:4700:4700::1111">>]],
    ?assert(vpndetection:is_bogon(Client, <<"192.168.1.1">>)),
    ?assertNot(vpndetection:is_bogon(Client, "1.1.1.1")).

%% Asserting the PEAK is the only way to tell a real limit from an option that
%% was accepted and ignored.
batch_concurrency_is_configurable_per_call_test() ->
    Stub = vpndetection_stub:start(routes(?ADDRS), 30),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),

    _ = vpndetection:lookup_batch(Client, ?ADDRS, #{concurrency => 3}),

    ?assertEqual(length(?ADDRS), vpndetection_stub:calls(Stub)),
    ?assert(vpndetection_stub:peak(Stub) =< 3),
    ?assert(vpndetection_stub:peak(Stub) > 1),
    vpndetection_stub:stop(Stub).

a_per_call_concurrency_overrides_the_client_default_test() ->
    Stub = vpndetection_stub:start(routes(?ADDRS), 30),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false,
                                concurrency => 2}),

    _ = vpndetection:lookup_batch(Client, ?ADDRS, #{concurrency => 6}),

    ?assert(vpndetection_stub:peak(Stub) > 2),
    ?assert(vpndetection_stub:peak(Stub) =< 6),
    vpndetection_stub:stop(Stub).

without_an_override_the_client_concurrency_still_applies_test() ->
    Stub = vpndetection_stub:start(routes(?ADDRS), 30),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false,
                                concurrency => 2}),

    _ = vpndetection:lookup_batch(Client, ?ADDRS),

    ?assertEqual(2, vpndetection_stub:peak(Stub)),
    vpndetection_stub:stop(Stub).

%% The stub proves the SDK spawns the right number of workers. This proves the
%% real transport then lets them all run: httpc admits max_sessions *
%% max_keep_alive_length requests at a time, so an untuned profile would throttle
%% a batch to ten however many workers were started.
the_real_transport_honors_the_concurrency_bound_test_() ->
    {timeout, 60, fun() ->
        Origin = vpndetection_origin:start(#{delay_ms => 150}),
        Addrs = [<<"9.9.9.", (integer_to_binary(N))/binary>> || N <- lists:seq(1, 24)],
        Client = vpndetection:new(#{base_url => vpndetection_origin:base_url(Origin),
                                    cache => false}),

        _ = vpndetection:lookup_batch(Client, Addrs, #{concurrency => 16}),

        ?assertEqual(16, vpndetection_origin:peak(Origin)),
        vpndetection_origin:stop(Origin)
    end}.

retries_are_configurable_per_call_test() ->
    Stub = vpndetection_stub:start(#{<<"9.9.9.9">> => #{status => 500,
                                                        body => #{<<"error">> => <<"lookup failed">>}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false, retries => 0}),

    ?assertMatch({error, #{kind := server_error}},
                 vpndetection:lookup(Client, <<"9.9.9.9">>, #{retries => 2})),
    ?assertEqual(3, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

a_429_is_retried_only_when_it_carries_retry_after_test_() ->
    {timeout, 30, fun() ->
        WithHeader = vpndetection_stub:start(#{
            <<"1.1.1.1">> => #{status => 429, headers => #{<<"Retry-After">> => <<"1">>},
                               body => #{<<"error">> => <<"rate limit exceeded">>}}}),
        Retried = vpndetection:new(#{http => vpndetection_stub:http(WithHeader), cache => false,
                                     retries => 1}),
        ?assertMatch({error, #{kind := rate_limited}}, vpndetection:lookup(Retried, <<"1.1.1.1">>)),
        ?assertEqual(2, vpndetection_stub:calls(WithHeader)),
        vpndetection_stub:stop(WithHeader),

        Spent = vpndetection_stub:start(#{
            <<"1.1.1.1">> => #{status => 429,
                               body => #{<<"error">> => <<"request allowance exceeded">>}}}),
        Once = vpndetection:new(#{http => vpndetection_stub:http(Spent), cache => false,
                                  retries => 3}),
        ?assertMatch({error, #{kind := quota_exceeded}}, vpndetection:lookup(Once, <<"1.1.1.1">>)),
        ?assertEqual(1, vpndetection_stub:calls(Spent)),
        vpndetection_stub:stop(Spent)
    end}.

%% The database responses nest their payload. `checksums' shipped broken in
%% another binding for exactly this reason: it read a top-level `sha256' that is
%% not there, and returned nothing against a perfectly healthy API.
database_responses_are_unwrapped_at_the_right_depth_test() ->
    Stub = vpndetection_stub:start(#{
        <<"/api/v1/database/checksum">> => #{body => #{
            <<"id">> => <<"vpn_ip_extended_v1">>, <<"format">> => <<"mmdb">>,
            <<"checksums">> => #{<<"md5">> => <<"m">>, <<"sha1">> => <<"s1">>,
                                 <<"sha256">> => <<"s256">>, <<"sha512">> => <<"s512">>}}},
        <<"/api/v1/database/list">> => #{body => #{
            <<"datasets">> => [#{<<"id">> => <<"vpn_ip_extended_v1">>}]}},
        <<"/api/v1/database/downloads">> => #{body => #{
            <<"downloads">> => [#{<<"dataset_id">> => <<"vpn_ip_extended_v1">>}]}},
        <<"/api/v1/database/metadata">> => #{body => #{
            <<"id">> => <<"vpn_ip_extended_v1">>, <<"entries">> => 42}}
    }),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), api_key => <<"k">>}),

    {ok, Sums} = vpndetection:database_checksums(Client, <<"vpn_ip_extended_v1">>, mmdb),
    ?assertEqual(#{<<"md5">> => <<"m">>, <<"sha1">> => <<"s1">>,
                   <<"sha256">> => <<"s256">>, <<"sha512">> => <<"s512">>}, Sums),
    ?assertEqual({ok, <<"s256">>}, maps:find(<<"sha256">>, Sums)),

    ?assertEqual({ok, [#{<<"id">> => <<"vpn_ip_extended_v1">>}]}, vpndetection:database_list(Client)),
    ?assertEqual({ok, [#{<<"dataset_id">> => <<"vpn_ip_extended_v1">>}]},
                 vpndetection:database_downloads(Client)),
    {ok, Metadata} = vpndetection:database_metadata(Client, <<"vpn_ip_extended_v1">>),
    ?assertEqual(<<"vpn_ip_extended_v1">>, maps:get(<<"id">>, Metadata)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%% The download endpoint answers 302 to object storage. Following it would pull a
%% dataset that runs to gigabytes into one binary, so the origin here promises
%% five of them and the assertion is that nobody ever asked for it.
the_download_redirect_is_returned_and_never_followed_test_() ->
    {timeout, 60, fun() ->
        Origin = vpndetection_origin:start(#{}),
        Base = vpndetection_origin:base_url(Origin),
        Client = vpndetection:new(#{base_url => Base, api_key => <<"k">>, cache => false,
                                    timeout_ms => 3000, retries => 0}),

        {ok, Url} = vpndetection:database_download_url(Client, <<"vpn_ip_extended_v1">>, mmdb),

        ?assertEqual(<<Base/binary, "/huge">>, Url),
        ?assertEqual(0, vpndetection_origin:hits(Origin, <<"/huge">>)),
        vpndetection_origin:stop(Origin)
    end}.

two_clients_never_share_a_cached_answer_test() ->
    Stub = vpndetection_stub:start(routes([<<"1.1.1.1">>])),
    A = vpndetection:new(#{http => vpndetection_stub:http(Stub), api_key => <<"key-a">>}),
    B = vpndetection:new(#{http => vpndetection_stub:http(Stub), api_key => <<"key-b">>}),

    {ok, _} = vpndetection:lookup(A, <<"1.1.1.1">>),
    {ok, _} = vpndetection:lookup(B, <<"1.1.1.1">>),

    %% Two keys can be on different plans and so entitled to different fields; a
    %% shared cache would serve one of them the other's shape.
    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection:close(A),
    vpndetection:close(B),
    vpndetection_stub:stop(Stub).

caching_can_be_turned_off_test() ->
    Stub = vpndetection_stub:start(routes([<<"1.1.1.1">>])),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),

    {ok, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    {ok, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),

    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

a_cached_answer_expires_test() ->
    Stub = vpndetection_stub:start(routes([<<"1.1.1.1">>])),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => #{ttl_ms => 50}}),

    {ok, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    {ok, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    ?assertEqual(1, vpndetection_stub:calls(Stub)),

    timer:sleep(80),
    {ok, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

the_cache_evicts_the_least_recently_used_entry_test() ->
    Addrs = [<<"9.9.9.1">>, <<"9.9.9.2">>, <<"9.9.9.3">>],
    Stub = vpndetection_stub:start(routes(Addrs)),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => #{max => 2}}),

    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.1">>),
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.2">>),
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.1">>),
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.3">>),
    ?assertEqual(3, vpndetection_stub:calls(Stub)),

    %% 9.9.9.2 was the least recently used when 9.9.9.3 arrived, so it is the one
    %% that had to be fetched again; 9.9.9.1 is still held.
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.1">>),
    ?assertEqual(3, vpndetection_stub:calls(Stub)),
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.2">>),
    ?assertEqual(4, vpndetection_stub:calls(Stub)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

errors_are_never_cached_test() ->
    Stub = vpndetection_stub:start(#{<<"1.1.1.1">> => #{status => 500,
                                                        body => #{<<"error">> => <<"lookup failed">>}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), retries => 0}),

    {error, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    {error, _} = vpndetection:lookup(Client, <<"1.1.1.1">>),

    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%% Decoding a server-supplied key straight to an atom is how an Erlang client
%% gets taken down by a response it does not control: the atom table is capped
%% and never collected. The dataset metadata carries arbitrary keys, so this is
%% not hypothetical.
a_response_full_of_unknown_keys_mints_no_atoms_test() ->
    Client = vpndetection:new(#{cache => false, http => fun(#{url := Url}) ->
        Ip = lists:last(binary:split(Url, <<"/">>, [global])),
        {ok, #{status => 200, headers => [], body => iolist_to_binary(json:encode(
            #{<<"ip">> => Ip, <<"is_vpn">> => false,
              <<"surprise_", Ip/binary>> => #{<<"nested_", Ip/binary>> => 1}}))}}
    end}),
    {ok, _} = vpndetection:lookup(Client, <<"9.9.9.1">>),

    Before = erlang:system_info(atom_count),
    [{ok, _} = vpndetection:lookup(Client, <<"9.9.9.", (integer_to_binary(N))/binary>>)
     || N <- lists:seq(100, 160)],
    ?assertEqual(Before, erlang:system_info(atom_count)).

a_transport_failure_is_an_error_not_a_crash_test() ->
    Client = vpndetection:new(#{base_url => <<"http://127.0.0.1:1">>, cache => false,
                                retries => 0, timeout_ms => 2000}),
    ?assertMatch({error, #{kind := network, retryable := true}},
                 vpndetection:lookup(Client, <<"1.1.1.1">>)).

routes(Addrs) ->
    maps:from_list([{Ip, #{body => #{<<"ip">> => Ip, <<"is_vpn">> => false}}} || Ip <- Addrs]).
