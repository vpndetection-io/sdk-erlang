%% Runs against the real API, and only when asked, so `rebar3 eunit' stays
%% offline and costs no quota:
%%
%%   VPNDETECTION_LIVE=1 rebar3 eunit --module=vpndetection_live_tests
%%
%% It asserts the free tier's shape, including that `is_hosting' is ABSENT
%% without a key, which is the one claim a stub cannot make honestly.
-module(vpndetection_live_tests).

-include_lib("eunit/include/eunit.hrl").

live_test_() ->
    case os:getenv("VPNDETECTION_LIVE") of
        "1" -> {timeout, 60, fun unauthenticated_lookup/0};
        _ -> []
    end.

unauthenticated_lookup() ->
    Client = vpndetection:new(#{}),

    {ok, Vpn} = vpndetection:lookup(Client, <<"45.83.91.1">>),
    ?assertEqual(<<"45.83.91.1">>, maps:get(ip, Vpn)),
    ?assertEqual(true, maps:get(is_vpn, Vpn)),
    ?assertEqual(false, maps:get(is_bogon, Vpn)),

    {ok, Plain} = vpndetection:lookup(Client, <<"1.1.1.1">>),
    ?assertEqual(false, maps:get(is_vpn, Plain)),
    %% Absent, not false: the free tier does not include the hosting dataset, so
    %% `maps:find/2' answers `error' where a paid plan would answer `{ok, _}'.
    ?assertEqual(error, maps:find(is_hosting, Plain)),
    ?assertEqual(false, maps:get(is_hosting, Plain, false)),
    ?assertEqual(undefined, maps:get(is_hosting, Plain, undefined)),

    {ok, V6} = vpndetection:lookup(Client, <<"2606:4700:4700::1111">>),
    ?assertEqual(<<"2606:4700:4700::1111">>, maps:get(ip, V6)),

    Batch = vpndetection:lookup_batch(Client, [<<"45.83.91.1">>, <<"1.1.1.1">>, <<"10.0.0.1">>]),
    ?assertEqual(3, map_size(Batch)),
    ?assertMatch({ok, #{is_bogon := true}}, maps:get(<<"10.0.0.1">>, Batch)),

    vpndetection:close(Client).
