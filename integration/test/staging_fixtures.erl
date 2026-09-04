%% The staging fixtures the test modules share: one client per tier, one lookup
%% per tier, and the shape rules that hold whatever the plan.
-module(staging_fixtures).

-export([staging/0, probe/0, members/0, client/1, answer/1, assert_served_by_tier/1,
         assert_shape/3, served_field/2, wire_keys/1, forget/0]).

-include_lib("eunit/include/eunit.hrl").

-define(STAGING, <<"https://api-staging.vpndetection.io">>).
%% A stable VPN address, and the one the README teaches.
-define(PROBE, <<"45.83.91.1">>).

staging() -> ?STAGING.
probe() -> ?PROBE.

%% One entry per dataset the API answers about. `required' is what a POPULATED
%% detail object carries on every tier; `optional' is the max-only remainder,
%% which is absent rather than empty on a lower plan.
members() ->
    Class = [<<"provider">>, <<"confidence">>, <<"last_seen">>],
    Proxy = [<<"provider">>, <<"first_seen">>, <<"last_seen">>, <<"hits">>,
             <<"hits_days_pct">>, <<"providers_num">>],
    #{
        <<"vpn">> => #{required => [<<"provider">>, <<"last_seen">>],
                       optional => [<<"confidence">>, <<"method">>]},
        <<"hosting">> => #{required => Class, optional => []},
        <<"relay">> => #{required => Class, optional => []},
        <<"tor">> => #{required => Class, optional => []},
        <<"cdn">> => #{required => Class, optional => []},
        <<"resproxy">> => #{required => Proxy, optional => []},
        <<"dcproxy">> => #{required => Proxy, optional => []},
        <<"mobproxy">> => #{required => Proxy, optional => []}
    }.

%% @doc A client for one rung, and the recorder watching what it sends.
%%
%% The base URL is set through the client's own option, which is what makes that
%% option worth testing at all.
client(Rung) ->
    Key = staging_tiers:key(Rung),
    Recorder = staging_recorder:start(Key),
    Options = #{base_url => ?STAGING, http => staging_recorder:http(Recorder)},
    Client = case Key of
        undefined -> vpndetection:new(Options);
        _ -> vpndetection:new(Options#{api_key => Key})
    end,
    {Client, Recorder}.

%% @doc One lookup per tier for the whole run, held across eunit's per-test
%% processes in `persistent_term' because each test runs in a process of its own
%% and an ETS table would die with whichever one asked first.
answer(#{tier := Tier} = Rung) ->
    case persistent_term:get({?MODULE, Tier}, undefined) of
        undefined ->
            Fixture = fetch(Rung),
            persistent_term:put({?MODULE, Tier}, Fixture),
            Fixture;
        Fixture ->
            Fixture
    end.

fetch(#{tier := Tier} = Rung) ->
    {Client, Recorder} = client(Rung),
    {ok, Result} = vpndetection:lookup(Client, ?PROBE),
    Carried = staging_recorder:carried_key(Recorder),
    vpndetection:close(Client),
    staging_recorder:stop(Recorder),
    %% Checked here rather than in one test, so no comparison anywhere can be
    %% made against a tier that silently ran unauthenticated: an empty or unsent
    %% key answers the free shape, which satisfies every containment check
    %% vacuously.
    case staging_tiers:key(Rung) of
        undefined -> ok;
        _ -> ?assert(Carried, binary_to_list(<<Tier/binary, ": the key never reached the wire">>))
    end,
    #{rung => Rung, result => Result, raw => maps:get(raw, Result), carried_key => Carried}.

%% @doc Drop the memoized answers. Only for a suite that has to look twice.
forget() ->
    [persistent_term:erase({?MODULE, Tier}) || #{tier := Tier} <- staging_tiers:rungs()],
    ok.

assert_served_by_tier(#{rung := #{tier := Tier}, result := Result, raw := Raw}) ->
    ?assertEqual({Tier, ?PROBE}, {Tier, maps:get(ip, Result)}),
    ?assertEqual({Tier, false}, {Tier, maps:get(is_bogon, Result)}),
    assert_shape(Tier, Result, Raw).

%% Holds on every plan: presence is the plan, the value is the answer.
assert_shape(Tier, Result, Raw) ->
    ?assert(is_binary(maps:get(<<"ip">>, Raw, undefined))),
    Served = maps:get(<<"is_vpn">>, Raw, missing),
    ?assert(is_boolean(Served), binary_to_list(<<Tier/binary, ": is_vpn is on every plan">>)),
    ?assertEqual({Tier, Served}, {Tier, maps:get(is_vpn, Result)}),
    maps:foreach(fun(Name, Spec) -> assert_member(Tier, Name, Spec, Result, Raw) end, members()).

assert_member(Tier, Name, Spec, Result, Raw) ->
    Flag = <<"is_", Name/binary>>,
    case maps:find(Flag, Raw) of
        {ok, Value} ->
            ?assert(is_boolean(Value),
                    binary_to_list(<<Tier/binary, ": ", Flag/binary, " must be a real boolean">>));
        error ->
            ok
    end,
    case maps:find(Name, Raw) of
        error ->
            ok;
        {ok, Object} ->
            %% A detail object without its flag would leave a caller reading the
            %% object to find out whether the address is flagged at all.
            ?assert(maps:is_key(Flag, Raw),
                    binary_to_list(<<Tier/binary, ": ", Name/binary, " is served without its flag">>)),
            assert_detail(Tier, Name, Spec, Object, maps:get(Flag, Raw), Result)
    end.

assert_detail(Tier, Name, Spec, Object, Flag, Result) ->
    ?assert(is_map(Object),
            binary_to_list(<<Tier/binary, ": ", Name/binary, " must be an object when present">>)),
    case map_size(Object) of
        0 ->
            ?assertEqual({Tier, Name, false}, {Tier, Name, Flag}),
            %% An empty object stays empty on the way through the mapper: filling
            %% it in would invent an answer the API did not give.
            ?assertEqual({Tier, Name, #{}}, {Tier, Name, element(2, served_field(Result, Name))});
        _ ->
            [?assert(maps:is_key(Key, Object),
                     binary_to_list(<<Tier/binary, ": ", Name/binary, " carries no ", Key/binary>>))
             || Key <- maps:get(required, Spec)],
            Documented = maps:get(required, Spec) ++ maps:get(optional, Spec),
            [?assert(lists:member(Key, Documented),
                     binary_to_list(<<Tier/binary, ": ", Name/binary, ".", Key/binary,
                                      " is not a documented key">>))
             || Key <- maps:keys(Object)]
    end.

%% @doc Looks a member up by its WIRE name, so a test says "this field is absent"
%% about the name the API serves rather than whatever the client called it.
%%
%% Both spellings are tried because the client turns only an allowlist of
%% spec-defined names into atoms and leaves everything else as a binary key.
served_field(Result, Wire) ->
    case maps:find(Wire, Result) of
        {ok, Value} ->
            {ok, Value};
        error ->
            case atom_of(Wire) of
                undefined -> error;
                Atom -> maps:find(Atom, Result)
            end
    end.

%% @doc The keys the wire actually carried, sorted.
wire_keys(#{raw := Raw}) ->
    lists:sort(maps:keys(Raw)).

atom_of(Wire) ->
    _ = code:ensure_loaded(vpndetection_result),
    try binary_to_existing_atom(Wire) catch error:badarg -> undefined end.
