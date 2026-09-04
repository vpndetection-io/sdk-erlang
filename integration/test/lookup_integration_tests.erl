%% The published package looking addresses up against the staging API.
%%
%% Nothing here pins a field COUNT. The tiers are asserted as a RELATION, each
%% one serving a superset of the tier below it, so a pricing change stays a
%% pricing change instead of arriving as a red SDK build. What a served answer
%% must satisfy on every tier: `ip' and `is_vpn' always; a present flag is a real
%% boolean; a field a higher tier serves is ABSENT on a lower one rather than
%% false; a populated detail object carries its documented keys; an empty one
%% means its flag is false.
-module(lookup_integration_tests).

-include_lib("eunit/include/eunit.hrl").

an_unauthenticated_lookup_answers_ip_and_is_vpn_test_() ->
    {timeout, 60, fun() ->
        Fixture = staging_fixtures:answer(staging_tiers:unauth()),
        Raw = maps:get(raw, Fixture),

        ?assertEqual(staging_fixtures:probe(), maps:get(<<"ip">>, Raw, missing)),
        ?assert(is_boolean(maps:get(<<"is_vpn">>, Raw, missing))),
        staging_fixtures:assert_served_by_tier(Fixture),
        io:format("testing against ~s~n", [staging_fixtures:staging()])
    end}.

a_key_reaches_the_wire_and_its_answer_keeps_its_shape_test_() ->
    [{binary_to_list(Tier), {timeout, 60, fun() -> keyed_tier(Rung) end}}
     || #{tier := Tier, secret := Secret} = Rung <- staging_tiers:rungs(), Secret =/= undefined].

keyed_tier(Rung) ->
    case staging_tiers:skip_reason(Rung) of
        undefined ->
            Fixture = staging_fixtures:answer(Rung),
            ?assert(maps:get(carried_key, Fixture)),
            staging_fixtures:assert_served_by_tier(Fixture);
        Reason ->
            %% eunit has no skip, so an unobservable tier is reported rather than
            %% silently passing as if it had been exercised.
            staging_tiers:notice("SKIPPED: " ++ Reason)
    end.

each_tier_serves_a_superset_of_the_tier_below_test_() ->
    {timeout, 120, fun() ->
        case staging_tiers:ladder_skip() of
            undefined -> ladder();
            Reason -> staging_tiers:notice("SKIPPED: " ++ Reason)
        end
    end}.

ladder() ->
    lists:foldl(fun(Rung, Below) ->
        Fixture = staging_fixtures:answer(Rung),
        Keys = staging_fixtures:wire_keys(Fixture),
        io:format("~s: ~b fields~n", [maps:get(tier, Rung), length(Keys)]),
        case Below of
            undefined ->
                ok;
            #{rung := #{tier := BelowTier}} ->
                BelowKeys = staging_fixtures:wire_keys(Below),
                [?assert(lists:member(Key, Keys),
                         binary_to_list(<<(maps:get(tier, Rung))/binary, " drops ", Key/binary,
                                          ", which ", BelowTier/binary, " serves">>))
                 || Key <- BelowKeys],
                %% Without this a run in which every key resolved to the same plan
                %% would pass: identical sets satisfy containment in both directions.
                case maps:get(widens, Rung) of
                    true ->
                        ?assert(length(Keys) > length(BelowKeys),
                                binary_to_list(<<(maps:get(tier, Rung))/binary, " is no wider than ",
                                                 BelowTier/binary>>));
                    false ->
                        ok
                end
        end,
        Fixture
    end, undefined, staging_tiers:observable()),
    ok.

%% The point of the whole result mapping: a plan-gated member the server did not
%% send must be MISSING from the map, which `maps:find/2' answers `error' for. A
%% client that filled it in with `false' would report "checked, and no" about a
%% dataset the plan never looked at.
a_field_a_higher_tier_serves_is_absent_on_a_lower_one_never_false_test_() ->
    {timeout, 120, fun() ->
        case staging_tiers:ladder_skip() of
            undefined -> absence();
            Reason -> staging_tiers:notice("SKIPPED: " ++ Reason)
        end
    end}.

absence() ->
    Fixtures = [staging_fixtures:answer(R) || R <- staging_tiers:observable()],
    %% The positive half: a field the wire carried must have reached the result,
    %% which is what makes a served `false' survive.
    [assert_served_survives(F) || F <- Fixtures],
    absent_below(Fixtures).

assert_served_survives(#{rung := #{tier := Tier}, result := Result} = Fixture) ->
    [?assertMatch({Tier, Key, {ok, _}}, {Tier, Key, staging_fixtures:served_field(Result, Key)})
     || Key <- staging_fixtures:wire_keys(Fixture)].

absent_below([]) ->
    ok;
absent_below([#{rung := #{tier := Tier}, result := Result} = Lower | Above]) ->
    OnTheWire = staging_fixtures:wire_keys(Lower),
    Higher = lists:usort(lists:append([staging_fixtures:wire_keys(F) || F <- Above])),
    [?assertEqual({Tier, Key, error}, {Tier, Key, staging_fixtures:served_field(Result, Key)})
     || Key <- Higher, not lists:member(Key, OnTheWire)],
    absent_below(Above).

a_bogon_is_answered_without_touching_the_network_test_() ->
    {timeout, 60, fun() ->
        Refusing = fun(_Request) -> {error, the_bogon_path_reached_the_network} end,
        Client = vpndetection:new(#{base_url => staging_fixtures:staging(), http => Refusing}),

        {ok, Result} = vpndetection:lookup(Client, <<"10.0.0.1">>),

        ?assertEqual(true, maps:get(is_bogon, Result)),
        ?assertEqual(false, maps:get(is_vpn, Result)),
        ?assert(vpndetection:is_bogon(<<"10.0.0.1">>)),
        ?assert(vpndetection:is_bogon(Client, <<"10.0.0.1">>)),
        %% Computed rather than served, so it carries every field whatever the
        %% plan, and a caller must not read their entitlement off one.
        maps:foreach(fun(Name, _Spec) ->
            ?assertEqual({Name, false}, {Name, maps:get(flag(Name), Result, missing)}),
            ?assertEqual({Name, #{}}, {Name, maps:get(object(Name), Result, missing)})
        end, staging_fixtures:members()),
        vpndetection:close(Client)
    end}.

a_batch_collapses_duplicates_and_keeps_bogons_off_the_wire_test_() ->
    {timeout, 120, fun() ->
        {Client, Recorder} = staging_fixtures:client(staging_tiers:unauth()),
        Probe = staging_fixtures:probe(),

        Got = vpndetection:lookup_batch(Client, [Probe, <<"8.8.8.8">>, Probe, <<"10.0.0.1">>,
                                                 <<"8.8.8.8">>]),

        ?assertEqual(3, map_size(Got)),
        ?assertEqual([<<"/", Probe/binary>>, <<"/8.8.8.8">>], staging_recorder:paths(Recorder)),
        ?assertMatch({ok, #{is_bogon := true}}, maps:get(<<"10.0.0.1">>, Got)),
        [?assertMatch({Ip, {ok, _}}, {Ip, maps:get(Ip, Got)}) || Ip <- [Probe, <<"8.8.8.8">>]],
        vpndetection:close(Client),
        staging_recorder:stop(Recorder)
    end}.

flag(Name) ->
    binary_to_existing_atom(<<"is_", Name/binary>>).

object(Name) ->
    binary_to_existing_atom(Name).
