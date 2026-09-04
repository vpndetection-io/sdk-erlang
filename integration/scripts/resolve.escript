#!/usr/bin/env escript
%% -*- erlang -*-

%% The two questions scripts/run.sh has to answer before it can trust a run, both
%% written in Erlang because the files involved ARE Erlang terms: rebar.config
%% holds the constraint and rebar.lock holds what was resolved, and consulting
%% them beats a grep that a reformat would quietly defeat.
%%
%%   resolve.escript published   the versions on hex that satisfy rebar.config,
%%                               ascending, one per line; nothing at all when the
%%                               package or a matching version does not exist
%%   resolve.escript resolved    what rebar.lock says the dependency came from,
%%                               as `pkg <version>', `other <term>' or `missing'
%%
%% An empty `published' is a SKIP and not a failure: before the first release
%% there is no artifact to test. Anything else that goes wrong exits non-zero,
%% so a network fault cannot be mistaken for an unpublished package.

-define(PACKAGE, "vpndetection").
-define(API, "https://hex.pm/api/packages/" ?PACKAGE).

main(["published"]) ->
    Constraint = constraint(),
    io:format(standard_error, "==> ~s ~s~n", [?PACKAGE, Constraint]),
    [io:format("~s~n", [V]) || V <- matching(Constraint, releases())];
main(["resolved"]) ->
    io:format("~s~n", [locked()]);
main(_) ->
    die("usage: resolve.escript published|resolved").

%% The constraint is read from rebar.config rather than repeated here, so the
%% gate and the resolver can never disagree about what is being asked for.
constraint() ->
    {ok, Terms} = file:consult("rebar.config"),
    Deps = proplists:get_value(deps, Terms, []),
    case lists:keyfind(list_to_atom(?PACKAGE), 1, Deps) of
        {_, C} when is_list(C) -> C;
        {_, C} when is_binary(C) -> binary_to_list(C);
        Other -> die(io_lib:format("rebar.config declares ~p, which is not a hex constraint",
                                   [Other]))
    end.

%% hex's own package API, which lists exactly the releases its repository serves,
%% so this is the set `rebar3' would resolve from. A 404 means the package has
%% never been published, which is the state before the first release.
releases() ->
    {ok, _} = application:ensure_all_started(inets),
    {ok, _} = application:ensure_all_started(ssl),
    Request = {?API, [{"user-agent", "vpndetection-sdk-integration"},
                      {"accept", "application/json"}]},
    case httpc:request(get, Request, [{timeout, 30000}], [{body_format, binary}]) of
        {ok, {{_, 200, _}, _, Body}} ->
            [V || #{<<"version">> := V} <- maps:get(<<"releases">>, json:decode(Body), [])];
        {ok, {{_, 404, _}, _, _}} ->
            [];
        {ok, {{_, Status, _}, _, _}} ->
            die(io_lib:format("hex answered ~b for ~s", [Status, ?API]));
        {error, Reason} ->
            die(io_lib:format("could not reach hex: ~p", [Reason]))
    end.

matching(Constraint, Releases) ->
    {Low, High} = bounds(Constraint),
    Versions = [parse(V) || V <- Releases, binary:match(V, [<<"-">>, <<"+">>]) =:= nomatch],
    [render(V) || V <- lists:sort([V || V <- Versions, V >= Low, High =:= any orelse V < High])].

%% `~> 1.0' means at least 1.0.0 and below 2.0.0: drop the last component of the
%% stated version and increment the one before it. That is hex's rule, and it is
%% the only operator this suite needs, so anything else fails loudly rather than
%% matching nothing and reading as "not published yet".
bounds("~>" ++ Rest) ->
    Raw = string:trim(Rest),
    {parse(Raw), ceiling(components(Raw))};
bounds(Exact) ->
    case parse(string:trim(Exact)) of
        [_ | _] = Version -> {Version, Version ++ [1]};
        _ -> die(["unsupported constraint ", Exact])
    end.

%% Padded to three components so 1.0 and 1.0.0 compare equal, which is what hex
%% means by them.
parse(Version) when is_binary(Version) ->
    parse(binary_to_list(Version));
parse(Version) ->
    Parts = [list_to_integer(P) || P <- string:lexemes(Version, ".")],
    Parts ++ lists:duplicate(erlang:max(0, 3 - length(Parts)), 0).

%% hex reads `~>' off the number of components WRITTEN, not off the padded
%% value: `~> 1.0' admits every 1.x, while `~> 1.0.0' stops before 1.1.0. Padding
%% to three and then incrementing the second-to-last component collapses those
%% two, so `~> 1.0' would stop matching the day 1.1.0 ships and this gate would
%% skip for ever - indistinguishable from "nothing published yet", which is the
%% one failure it must never imitate.
components(Raw) ->
    [list_to_integer(P) || P <- string:lexemes(Raw, ".")].

ceiling([Major]) -> [Major + 1, 0, 0];
ceiling([Major, _Minor]) -> [Major + 1, 0, 0];
ceiling([Major, Minor, _Patch]) -> [Major, Minor + 1, 0];
ceiling(Other) ->
    die(io_lib:format("~b-component constraint is not one hex defines", [length(Other)])).

render(Version) ->
    lists:join(".", [integer_to_list(P) || P <- Version]).

%% rebar.lock names the SOURCE, not just the version. A hex package locks as
%% `{pkg, Name, Vsn}'; a `{path, ...}' dependency is not locked at all and a git
%% one locks as `{git, ...}', so the shape is what proves the tests will run
%% against a release rather than against the source next door.
locked() ->
    case file:consult("rebar.lock") of
        {ok, Terms} -> entry(deps(Terms));
        {error, enoent} -> "missing"
    end.

deps([{_Version, Deps} | _]) -> Deps;
deps([Deps | _]) when is_list(Deps) -> Deps;
deps(_) -> [].

entry(Deps) ->
    case lists:keyfind(list_to_binary(?PACKAGE), 1, Deps) of
        {_, {pkg, _, Vsn}, _} -> ["pkg ", Vsn];
        {_, Source, _} -> io_lib:format("other ~p", [Source]);
        false -> "missing"
    end.

die(Message) ->
    io:format(standard_error, "FAILED: ~s~n", [Message]),
    halt(1).
