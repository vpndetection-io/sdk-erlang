%% The Erlang-specific API surface, as distinct from the shared conformance
%% corpus in vpndetection_conformance_tests.
-module(vpndetection_client_tests).

-include_lib("eunit/include/eunit.hrl").

%% Enough addresses for seven chunks of the batch endpoint's 1000, so a
%% concurrency bound has something to bound: one request per chunk, and only
%% the chunks overlap.
-define(ADDRS, [addr(N) || N <- lists:seq(0, 6000)]).

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

    ?assertEqual(7, vpndetection_stub:calls(Stub)),
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
        %% Seventeen chunks of the batch endpoint's 1000, so sixteen workers each
        %% hold a request at once.
        Addrs = [addr(N) || N <- lists:seq(0, 16000)],
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
            <<"databases">> => [#{
                <<"base">> => <<"vpn_ip_extended">>, <<"name">> => <<"VPN IP Extended">>,
                <<"summary">> => <<"extended rows">>,
                <<"standing">> => <<"licensed">>, <<"in_term">> => true,
                <<"license_type">> => <<"standard">>,
                <<"starts">> => <<"2026-01-01T00:00:00.000Z">>, <<"expires">> => null,
                <<"renews_at">> => null, <<"notice_due_at">> => null,
                <<"versions">> => [#{<<"id">> => <<"vpn_ip_extended_v1">>, <<"version">> => 1,
                                     <<"formats">> => [#{<<"format">> => <<"mmdb">>,
                                                         <<"bytes">> => 42}]}]}]}},
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

    %% A licence covers a FAMILY, and the id a download takes lives one level down
    %% under `versions'. The spec used to claim the family carried an `id' and a
    %% `formats' of its own, so a caller who believed it had no way to name a
    %% downloadable dataset at all.
    {ok, [Family]} = vpndetection:database_list(Client),
    ?assertEqual(<<"vpn_ip_extended">>, maps:get(<<"base">>, Family)),
    ?assertEqual(error, maps:find(<<"id">>, Family)),
    ?assertEqual([<<"vpn_ip_extended_v1">>],
                 [maps:get(<<"id">>, V) || V <- maps:get(<<"versions">>, Family)]),
    ?assertEqual({ok, [#{<<"dataset_id">> => <<"vpn_ip_extended_v1">>}]},
                 vpndetection:database_downloads(Client)),
    {ok, Metadata} = vpndetection:database_metadata(Client, <<"vpn_ip_extended_v1">>),
    ?assertEqual(<<"vpn_ip_extended_v1">>, maps:get(<<"id">>, Metadata)),
    vpndetection:close(Client),
    vpndetection_stub:stop(Stub).

%% The limit asked for is the one on the wire, and none goes out unless asked for,
%% so the default and the clamp stay the server's to change.
the_downloads_limit_reaches_the_query_string_only_when_asked_for_test() ->
    Stub = vpndetection_stub:start(#{<<"/api/v1/database/downloads">> =>
        #{body => #{<<"downloads">> => []}}}),
    Http = vpndetection_stub:http(Stub),
    Parent = self(),
    Recording = fun(#{url := Url} = Request) ->
        Parent ! {requested, Url},
        Http(Request)
    end,
    Client = vpndetection:new(#{http => Recording, api_key => <<"k">>, cache => false}),

    {ok, []} = vpndetection:database_downloads(Client, #{limit => 7}),
    {ok, []} = vpndetection:database_downloads(Client),
    {ok, []} = vpndetection:database_downloads(Client, #{timeout_ms => 5000}),

    ?assertEqual([{<<"/api/v1/database/downloads">>, [{<<"limit">>, <<"7">>}]},
                  {<<"/api/v1/database/downloads">>, []},
                  {<<"/api/v1/database/downloads">>, []}],
                 [path_and_query(Url) || Url <- requested([])]),
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

        %% The origin points its redirect at the file the requested id names, and
        %% `huge' is the one that announces five gigabytes and then stalls.
        {ok, Url} = vpndetection:database_download_url(Client, <<"huge">>, mmdb),

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

%% The per-call bound is set BELOW the client's against an origin that stalls
%% past both, so a call that ignored it would wait out the client's bound
%% instead, and the elapsed time says which one fired.
a_per_call_timeout_below_the_clients_is_the_one_that_fires_test_() ->
    {timeout, 60, fun() ->
        Origin = vpndetection_origin:start(#{delay_ms => 8000}),
        Client = vpndetection:new(#{base_url => vpndetection_origin:base_url(Origin),
                                    cache => false, retries => 0, timeout_ms => 4000}),
        PerCall = #{timeout_ms => 300},
        Calls = [
            {lookup, fun() -> vpndetection:lookup(Client, <<"1.1.1.1">>, PerCall) end},
            {my_ip, fun() -> vpndetection:my_ip(Client, PerCall) end},
            {my_entitlement, fun() -> vpndetection:my_entitlement(Client, PerCall) end},
            {lookup_batch, fun() ->
                maps:get(<<"1.1.1.1">>, vpndetection:lookup_batch(Client, [<<"1.1.1.1">>], PerCall))
            end}
        ],

        [begin
             {Micros, Answer} = timer:tc(Call),
             ?assertMatch({Name, {error, #{kind := network, retryable := true}}}, {Name, Answer}),
             ?assertEqual({Name, fired_within_2s}, {Name, elapsed(Micros, 2000000)})
         end || {Name, Call} <- Calls],
        vpndetection_origin:stop(Origin)
    end}.

%% No cap on what one call accepts: chunking to the endpoint's 1000 is the
%% client's job, so 2,500 addresses are three requests rather than an error.
a_batch_of_2500_addresses_is_three_requests_and_one_answer_each_test() ->
    Addrs = [addr(N) || N <- lists:seq(0, 2499)],
    Stub = vpndetection_stub:start(routes(Addrs)),
    Http = vpndetection_stub:http(Stub),
    Parent = self(),
    Recording = fun(#{method := Method, url := Url} = Request) ->
        Ips = maps:get(<<"ips">>, json:decode(maps:get(body, Request, <<"{}">>)), []),
        Parent ! {sent, Method, maps:get(path, uri_string:parse(Url)), length(Ips)},
        Http(Request)
    end,
    Client = vpndetection:new(#{http => Recording, cache => false}),

    Got = vpndetection:lookup_batch(Client, Addrs),

    ?assertEqual([{post, <<"/batch">>, 500}, {post, <<"/batch">>, 1000}, {post, <<"/batch">>, 1000}],
                 lists:sort(sent([]))),
    ?assertEqual(2500, map_size(Got)),
    [?assertMatch({ok, #{ip := Ip}}, maps:get(Ip, Got)) || Ip <- Addrs],
    vpndetection_stub:stop(Stub).

%% A dispatcher that may run nothing waits for ever, so a concurrency below 1 is
%% refused before any request, for every address it was given.
a_batch_concurrency_below_one_is_refused_before_any_request_test() ->
    Stub = vpndetection_stub:start(#{}),
    Http = vpndetection_stub:http(Stub),
    Client = vpndetection:new(#{http => Http, cache => false}),
    Ips = [<<"9.9.9.9">>, <<"10.0.0.1">>],

    [?assertEqual({Limit, lists:sort(Ips), [bad_request, bad_request]},
                  {Limit, lists:sort(maps:keys(Got)), [Kind || {error, #{kind := Kind}} <- maps:values(Got)]})
     || Limit <- [0, -1, 1.5],
        Got <- [vpndetection:lookup_batch(Client, Ips, #{concurrency => Limit})]],
    Zero = vpndetection:new(#{http => Http, cache => false, concurrency => 0}),
    ?assertMatch(#{<<"9.9.9.9">> := {error, #{kind := bad_request, retryable := false}}},
                 vpndetection:lookup_batch(Zero, [<<"9.9.9.9">>])),
    ?assertEqual(0, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

%% The bound must cover the BODY: one that stops at the response head lets a body
%% stalled after its headers run for as long as the server likes.
a_body_stalled_after_its_headers_is_bounded_test_() ->
    {timeout, 60, fun() -> assert_body_bounded({stall, 8000}) end}.

%% A byte every 20 ms never leaves one read waiting long, so only a bound on the
%% whole attempt ends it.
a_body_trickled_a_byte_at_a_time_is_bounded_test_() ->
    {timeout, 60, fun() -> assert_body_bounded({trickle, 20}) end}.

%% The runtime lists are written by hand, so each is pinned to the committed spec
%% in BOTH directions: a value the spec gains or drops fails here on the re-pin.
the_exported_vocabularies_are_the_pinned_specs_test() ->
    ?assertEqual(lists:sort(spec_enum(<<"    DatabaseFormat:">>)),
                 lists:sort([atom_to_binary(F) || F <- vpndetection:database_formats()])),
    ?assertEqual(lists:sort(spec_enum(<<"    Standing:">>)), lists:sort(vpndetection:standings())),
    ?assertEqual(lists:sort(spec_license_types()), lists:sort(vpndetection:license_types())).

%% `format()' checks nothing once compiled, so an atom from a flag or a config
%% file has to be refused at runtime, before it costs a request.
an_unpublished_format_is_refused_before_any_request_test() ->
    Stub = vpndetection_stub:start(#{}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),
    Dir = list_to_binary(os:getenv("TMPDIR", "/tmp")),
    Path = <<Dir/binary, "/vpndetection-", (integer_to_binary(erlang:unique_integer([positive])))/binary,
             "-refused.mmdb">>,
    Calls = [
        fun(F) -> vpndetection:database_checksums(Client, <<"vpn_ip_v1">>, F) end,
        fun(F) -> vpndetection:database_download_url(Client, <<"vpn_ip_v1">>, F) end,
        fun(F) -> vpndetection:database_download(Client, <<"vpn_ip_v1">>, F, Path) end,
        fun(F) -> vpndetection:database_download_bytes(Client, <<"vpn_ip_v1">>, F) end
    ],

    [?assertMatch({Format, {error, #{kind := bad_request, retryable := false}}},
                  {Format, Call(Format)})
     || Format <- [zip, 'MMDB', <<"mmdb">>, "csvgz"], Call <- Calls],
    ?assertEqual(0, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

%% The runtime list is written by hand, so it is pinned to the committed spec: a
%% format the spec gains fails here on the re-pin rather than being refused.
every_format_the_pinned_spec_publishes_is_accepted_test() ->
    Published = spec_formats(),
    ?assertNotEqual([], Published),
    Stub = vpndetection_stub:start(#{<<"/api/v1/database/download">> =>
        #{status => 302, headers => #{<<"Location">> => <<"https://storage.example/f">>}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), cache => false}),

    [?assertEqual({Format, {ok, <<"https://storage.example/f">>}},
                  {Format, vpndetection:database_download_url(Client, <<"vpn_ip_v1">>,
                                                              binary_to_atom(Format))})
     || Format <- Published],
    ?assertEqual(length(Published), vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

%% Each call's own bound (300 ms) fires first, then a call with no override waits
%% for the client's (1 s), and the elapsed time says which one fired.
assert_body_bounded(Pace) ->
    Origin = vpndetection_origin:start(#{body_pace => Pace}),
    Client = vpndetection:new(#{base_url => vpndetection_origin:base_url(Origin),
                                cache => false, retries => 0, timeout_ms => 1000}),
    PerCall = #{timeout_ms => 300},
    Calls = [
        {lookup, {250, 900}, fun() -> vpndetection:lookup(Client, <<"1.1.1.1">>, PerCall) end},
        {lookup_batch, {250, 900}, fun() ->
            maps:get(<<"1.1.1.1">>, vpndetection:lookup_batch(Client, [<<"1.1.1.1">>], PerCall))
        end},
        {oauth_exchange, {250, 900}, fun() ->
            vpndetection:oauth_exchange_device_code(Client, <<"cli">>, <<"mo_dc_x">>, PerCall)
        end},
        {database_downloads, {250, 900}, fun() -> vpndetection:database_downloads(Client, PerCall) end},
        {my_entitlement, {900, 2500}, fun() -> vpndetection:my_entitlement(Client) end},
        {database_list, {900, 2500}, fun() -> vpndetection:database_list(Client) end},
        {database_downloads_default, {900, 2500}, fun() -> vpndetection:database_downloads(Client) end},
        {oauth_metadata, {900, 2500}, fun() -> vpndetection:oauth_metadata(Client) end}
    ],
    [begin
         {Micros, Answer} = timer:tc(Call),
         ?assertMatch({Name, {error, #{kind := network, retryable := true}}}, {Name, Answer}),
         Ms = Micros div 1000,
         ?assertEqual({Name, within, Window}, {Name, within(Ms, Window), Window})
     end || {Name, Window, Call} <- Calls],
    vpndetection_origin:stop(Origin).

within(Ms, {Low, High}) when Ms >= Low, Ms < High -> within;
within(Ms, _Window) -> {took_ms, Ms}.

elapsed(Micros, Limit) when Micros < Limit -> fired_within_2s;
elapsed(Micros, _Limit) -> {took_us, Micros}.

sent(Acc) ->
    receive
        {sent, Method, Path, Size} -> sent([{Method, Path, Size} | Acc])
    after 0 ->
        Acc
    end.

requested(Acc) ->
    receive
        {requested, Url} -> requested([Url | Acc])
    after 0 ->
        lists:reverse(Acc)
    end.

path_and_query(Url) ->
    Parsed = uri_string:parse(Url),
    {maps:get(path, Parsed), uri_string:dissect_query(maps:get(query, Parsed, <<>>))}.

%% The `DatabaseFormat' enum, read by line because OTP ships no YAML parser. The
%% schema's body is every line indented past its name, so another schema's enum
%% cannot be read in its place.
spec_formats() ->
    spec_enum(<<"    DatabaseFormat:">>).

spec_enum(SchemaLine) ->
    [_ | Rest] = lists:dropwhile(fun(Line) -> Line =/= SchemaLine end, spec_lines()),
    Schema = lists:takewhile(fun(Line) -> binary:match(Line, <<"      ">>) =:= {0, 6} end, Rest),
    [Value || <<"        - ", Value/binary>> <- Schema].

%% `license_type' is an inline enum on the family, nullable, so `null' is not one
%% of its values.
spec_license_types() ->
    [_ | Rest] = lists:dropwhile(fun(Line) -> Line =/= <<"        license_type:">> end, spec_lines()),
    Property = lists:takewhile(fun(Line) -> binary:match(Line, <<"          ">>) =:= {0, 10} end, Rest),
    [Value || <<"            - ", Value/binary>> <- Property, Value =/= <<"null">>].

spec_lines() ->
    {ok, Yaml} = file:read_file("spec/openapi.yaml"),
    binary:split(Yaml, <<"\n">>, [global]).

addr(N) ->
    list_to_binary(io_lib:format("9.~b.~b.~b", [1 + N div 65536, (N div 256) rem 256, N rem 256])).

routes(Addrs) ->
    maps:from_list([{Ip, #{body => #{<<"ip">> => Ip, <<"is_vpn">> => false}}} || Ip <- Addrs]).

account_body() ->
    #{<<"org_id">> => <<"85bb51e4-2eb6-4a31-8e4d-02ba8b98fe61">>,
      <<"apikey">> => #{<<"id">> => <<"0ab424cc-7619-4dad-b027-afacdc2cedb0">>,
                        <<"expires">> => null,
                        <<"allowed_cidrs">> => []},
      <<"plan">> => #{<<"key">> => <<"max">>, <<"tier">> => <<"max">>},
      <<"usage">> => #{<<"requests">> => 580,
                       <<"quota">> => 5000000,
                       <<"hard_limit">> => null,
                       <<"window_start">> => <<"2026-09-04T07:00:00Z">>,
                       <<"window_end">> => <<"2026-10-04T07:00:00Z">>}}.

my_ip_classifies_the_calling_address_test() ->
    Stub = vpndetection_stub:start(#{<<"/myip">> =>
        #{body => #{<<"ip">> => <<"45.83.91.1">>, <<"is_vpn">> => true}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),

    {ok, Result} = vpndetection:my_ip(Client),

    ?assertEqual(<<"45.83.91.1">>, maps:get(ip, Result)),
    ?assertEqual(true, maps:get(is_vpn, Result)),
    vpndetection_stub:stop(Stub).

%% The cache is keyed by address, and which address this is IS the question.
my_ip_is_not_cached_test() ->
    Stub = vpndetection_stub:start(#{<<"/myip">> =>
        #{body => #{<<"ip">> => <<"45.83.91.1">>, <<"is_vpn">> => true}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),

    {ok, _} = vpndetection:my_ip(Client),
    {ok, _} = vpndetection:my_ip(Client),

    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

my_entitlement_reports_the_plan_and_the_usage_test() ->
    Stub = vpndetection_stub:start(#{<<"/api/v1/entitlement">> => #{body => account_body()}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),

    {ok, Account} = vpndetection:my_entitlement(Client),

    ?assertEqual(<<"max">>, maps:get(<<"key">>, maps:get(<<"plan">>, Account))),
    ?assertEqual(<<"max">>, maps:get(<<"tier">>, maps:get(<<"plan">>, Account))),
    Usage = maps:get(<<"usage">>, Account),
    ?assertEqual(580, maps:get(<<"requests">>, Usage)),
    ?assertEqual(5000000, maps:get(<<"quota">>, Usage)),
    %% null means NEVER stop, which is not the same as a limit of zero.
    ?assertEqual(null, maps:get(<<"hard_limit">>, Usage)),
    ?assertEqual([], maps:get(<<"allowed_cidrs">>, maps:get(<<"apikey">>, Account))),
    vpndetection_stub:stop(Stub).

%% The whole point is what has been spent.
my_entitlement_is_not_cached_test() ->
    Stub = vpndetection_stub:start(#{<<"/api/v1/entitlement">> => #{body => account_body()}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub)}),

    {ok, _} = vpndetection:my_entitlement(Client),
    {ok, _} = vpndetection:my_entitlement(Client),

    ?assertEqual(2, vpndetection_stub:calls(Stub)),
    vpndetection_stub:stop(Stub).

%% Unlike a lookup there is no useful unauthenticated answer.
my_entitlement_surfaces_an_unauthorized_key_test() ->
    Stub = vpndetection_stub:start(#{<<"/api/v1/entitlement">> =>
        #{status => 401, body => #{<<"error">> => <<"invalid API key">>}}}),
    Client = vpndetection:new(#{http => vpndetection_stub:http(Stub), retries => 0}),

    ?assertMatch({error, #{kind := unauthorized}}, vpndetection:my_entitlement(Client)),
    vpndetection_stub:stop(Stub).
