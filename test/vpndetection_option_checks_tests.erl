%% Options no call could use are refused where they are given: a client's in
%% new/1, a call's as a bad_request before any request, and a middleware's when
%% it is built.
-module(vpndetection_option_checks_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IP, <<"66.249.66.1">>).

%%% ------------------------------------------------------------------ the cache

a_cache_option_no_lookup_could_use_is_refused_when_the_client_is_built_test_() ->
    Bad = [{ttl_ms, infinity}, {ttl_ms, "x"}, {ttl_ms, 0}, {ttl_ms, -1}, {ttl_ms, 1.5},
           {max, -1}, {max, 0}, {max, infinity}, {max, "x"}],
    [{lists:flatten(io_lib:format("~p => ~p", [Name, V])),
      ?_assertError({badarg, {cache, {Name, V}}}, vpndetection:new(#{cache => #{Name => V}, http => http()}))}
     || {Name, V} <- Bad]
    ++ [{lists:flatten(io_lib:format("cache => ~p", [V])),
         ?_assertError({badarg, {cache, V}}, vpndetection:new(#{cache => V, http => http()}))}
        || V <- [true, undefined, [{max, 5}]]].

a_cache_of_one_entry_and_one_millisecond_builds_and_serves_test() ->
    {Http, Count} = counting(answer()),
    Client = vpndetection:new(#{api_key => <<"k">>, cache => #{max => 1, ttl_ms => 1}, http => Http}),
    {ok, _} = vpndetection:lookup(Client, ?IP),
    {ok, _} = vpndetection:lookup(Client, <<"66.249.66.2">>),
    ?assertEqual(2, counters:get(Count, 1)),
    vpndetection:close(Client).

%%% ------------------------------------------------------------------- helpers

answer() ->
    <<"{\"ip\":\"66.249.66.1\",\"is_vpn\":false}">>.

counting(Body) ->
    Count = counters:new(1, []),
    {fun(_) -> counters:add(Count, 1, 1), {ok, #{status => 200, headers => [], body => Body}} end, Count}.

http() ->
    fun(_) -> {ok, #{status => 200, headers => [], body => answer()}} end.
