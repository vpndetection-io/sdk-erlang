%% Which plan tiers this run can observe, and the secret each one needs.
%%
%% A tier is observable only when its secret holds something non-empty. Actions
%% interpolates a secret that does not exist to an EMPTY STRING rather than
%% leaving the variable unset, and a client built with an empty key sends no
%% authorization header at all, so an empty key runs as a second unauthenticated
%% client and every comparison against it is vacuously true.
-module(staging_tiers).

-export([rungs/0, unauth/0, max/0, observable/0, key/1, skip_reason/1, ladder_skip/0, notice/1]).

-export_type([rung/0]).

-type rung() :: #{tier := binary(), secret := binary() | undefined, widens := boolean()}.

%% Ascending, one rung per plan tier. `widens' is what the rung promises against
%% whichever observable rung sits below it: a paid tier serves strictly more than
%% the tier under it, while a free key and no key at all are the same entitlement
%% reached two ways.
%%
%% Field COUNTS are deliberately absent. Pinning "starter answers seven fields"
%% turns a pricing change into a red SDK build; the relation between the tiers is
%% what the client actually has to keep.
-spec rungs() -> [rung()].
rungs() ->
    [
        #{tier => <<"unauth">>, secret => undefined, widens => false},
        #{tier => <<"free">>, secret => "VPNDETECTION_STAGING_KEY_FREE", widens => false},
        #{tier => <<"starter">>, secret => "VPNDETECTION_STAGING_KEY_STARTER", widens => true},
        #{tier => <<"scale">>, secret => "VPNDETECTION_STAGING_KEY_SCALE", widens => true},
        #{tier => <<"max">>, secret => "VPNDETECTION_STAGING_KEY_MAX", widens => true}
    ].

-spec unauth() -> rung().
unauth() ->
    hd(rungs()).

-spec max() -> rung().
max() ->
    lists:last(rungs()).

-spec observable() -> [rung()].
observable() ->
    [R || R <- rungs(), skip_reason(R) =:= undefined].

%% @doc The key for a rung, or `undefined' when it has none to present.
-spec key(rung()) -> binary() | undefined.
key(#{secret := undefined}) ->
    undefined;
key(#{secret := Secret}) ->
    case string:trim(os:getenv(Secret, "")) of
        "" -> undefined;
        Key -> list_to_binary(Key)
    end.

%% @doc A reason to skip, or `undefined' when the rung can be exercised.
-spec skip_reason(rung()) -> string() | undefined.
skip_reason(#{secret := undefined}) ->
    undefined;
skip_reason(#{secret := Secret, tier := Tier} = Rung) ->
    case key(Rung) of
        undefined ->
            lists:flatten(io_lib:format("~s is not set, so the ~s tier cannot be exercised",
                                        [Secret, Tier]));
        _ ->
            undefined
    end.

%% @doc The ladder needs two rungs to say anything. The unauthenticated one is
%% always there, so this only fires when no tier secret at all is configured.
-spec ladder_skip() -> string() | undefined.
ladder_skip() ->
    case length(observable()) > 1 of
        true -> undefined;
        false -> "no tier secret is set, so there is no ladder to compare"
    end.

%% @doc Surfaced on the workflow run itself, so a skip is visible without opening
%% the log and reading to the end of it.
-spec notice(string()) -> ok.
notice(Message) ->
    case os:getenv("GITHUB_ACTIONS") of
        "true" -> io:format("::notice title=Integration::~s~n", [Message]);
        _ -> io:format("==> ~s~n", [Message])
    end.
