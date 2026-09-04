%% The licensed-download half, which only the max key can reach: it is the tier
%% holding dataset licences, and `db.download' is a scope the other three keys do
%% not carry.
%%
%% The transfer is budgeted before it starts. Metadata publishes a size per
%% format, and that size is checked against the ceiling below FIRST, so a
%% mistaken dataset id can never quietly pull one of the gigabyte datasets
%% through CI.
-module(database_integration_tests).

-include_lib("eunit/include/eunit.hrl").

%% The max organization licenses cdn_ip for redistribution, and at ~10 KB it is
%% the only dataset small enough to move in CI.
-define(DATASET, <<"cdn_ip_v1">>).
-define(FORMAT, csvgz).
%% 8 MiB against a ~10 KB dataset. Three orders of magnitude of headroom, so
%% tripping it means the suite is pointed somewhere unintended, which is exactly
%% when a transfer must not go ahead.
-define(CEILING, 8 * 1024 * 1024).
%% A real catalogue id the max organization holds no licence for.
-define(UNLICENSED, <<"hosting_ip_v1">>).
-define(DOWNLOAD_PATH, <<"/api/v1/database/download">>).

the_licensed_catalogue_answers_the_family_shape_test_() ->
    max_test(fun() ->
        {Client, Recorder} = max_client(),

        {ok, Families} = vpndetection:database_list(Client),

        ?assertNotEqual([], Families),
        Keys = lists:usort(lists:append([maps:keys(F) || F <- Families])),
        %% The corrected shape. Before the spec was fixed a family claimed an
        %% `id' and a `formats' of its own, so `database_list/1' could not tell a
        %% caller what to download at all.
        [?assert(lists:member(Key, Keys),
                 binary_to_list(<<"the payload carries ", (list_to_binary(lists:join(", ",
                     [binary_to_list(K) || K <- Keys])))/binary, " and not ", Key/binary>>))
         || Key <- [<<"base">>, <<"versions">>, <<"standing">>]],
        ?assertNot(lists:member(<<"docsGroup">>, Keys)),
        ?assertNot(lists:member(<<"id">>, Keys)),

        Ids = lists:append([assert_family(F) || F <- Families]),
        io:format("licensed: ~s~n", [lists:join(", ", [binary_to_list(I) || I <- Ids])]),
        done(Client, Recorder)
    end).

assert_family(Family) ->
    Base = maps:get(<<"base">>, Family, missing),
    ?assert(is_binary(Base) andalso Base =/= <<>>),
    ?assert(is_binary(maps:get(<<"name">>, Family, missing))),
    ?assert(lists:member(maps:get(<<"standing">>, Family, missing),
                         [<<"expired">>, <<"licensed">>, <<"unlicensed">>])),
    ?assert(lists:member(maps:get(<<"redistribution">>, Family, missing),
                         [<<"evaluation">>, <<"internal">>, <<"redistribute">>])),
    Versions = maps:get(<<"versions">>, Family, []),
    ?assertNotEqual({Base, []}, {Base, Versions}),
    [begin
         ?assert(is_binary(maps:get(<<"id">>, V, missing))),
         ?assert(is_integer(maps:get(<<"version">>, V, missing))),
         ?assertNotEqual({Base, []}, {Base, maps:get(<<"formats">>, V, [])})
     end || V <- Versions],
    [maps:get(<<"id">>, V) || V <- Versions].

%% A licence refusal names itself in `rc'. Falling back to the status means the
%% client never read the envelope, and the caller cannot tell "never bought this"
%% from "your term lapsed" without asking us.
a_dataset_the_organization_does_not_license_is_refused_cleanly_test_() ->
    max_test(fun() ->
        {Client, Recorder} = max_client(),

        Result = vpndetection:database_download_url(Client, ?UNLICENSED, ?FORMAT),

        ?assertMatch({error, #{kind := forbidden, status := 403, retryable := false}}, Result),
        {error, #{message := Message}} = Result,
        ?assertNotEqual(nomatch, binary:match(Message, <<"NOT_LICENSED">>)),
        ?assertEqual(nomatch, binary:match(Message, <<"request failed with status">>)),
        %% A 4xx is a client error. Two requests here would mean the classifier
        %% fell through to the retryable default.
        ?assertEqual(1, staging_recorder:requests(Recorder)),
        done(Client, Recorder)
    end).

a_dataset_is_streamed_to_disk_and_matches_its_published_digest_test_() ->
    max_test(fun() ->
        #{written := Written, path := Path, checksums := Sums} = transfer(),

        ?assert(Written > 0),
        ?assertEqual({ok, Written}, file_size(Path)),
        %% The working file is gone, so nothing half-written can be mistaken for
        %% a dataset by whatever reads the directory next.
        ?assertEqual(false, filelib:is_file(<<Path/binary, ".part">>)),
        {ok, Body} = file:read_file(Path),
        ?assertMatch(<<16#1f, 16#8b, _/binary>>, Body),

        %% Unwrapped past the `checksums' envelope. Reading a top-level `sha256'
        %% returns nothing against a perfectly healthy API, which is how another
        %% binding shipped this broken.
        Sha256 = maps:get(<<"sha256">>, Sums, missing),
        ?assertMatch(<<_:64/binary>>, Sha256),
        ?assertEqual(Sha256, digest(Body))
    end).

the_bytes_variant_agrees_with_the_streamed_copy_test_() ->
    max_test(fun() ->
        #{written := Written, checksums := Sums} = transfer(),
        {Client, Recorder} = max_client(),

        {ok, Bytes} = vpndetection:database_download_bytes(Client, ?DATASET, ?FORMAT),

        ?assertEqual(Written, byte_size(Bytes)),
        ?assertEqual(maps:get(<<"sha256">>, Sums, missing), digest(Bytes)),
        done(Client, Recorder)
    end).

%% The presigned URL authorizes itself, so the request that follows the 302 must
%% carry no credential. The mistake is invisible from the client side: the
%% transfer succeeds either way, and the key is simply gone.
no_credential_is_sent_to_object_storage_test_() ->
    max_test(fun() ->
        #{facts := Facts} = transfer(),
        Staging = staging_fixtures:staging(),

        Storage = [F || #{origin := Origin} = F <- Facts, Origin =/= Staging],
        ?assertNotEqual([], Storage),
        [?assertEqual({Origin, false}, {Origin, Carried})
         || #{origin := Origin, carried_key := Carried} <- Storage],
        %% And the API half did present it, so the check above is about where the
        %% key went rather than about a client that never had one.
        ?assert(lists:any(fun(#{origin := O, carried_key := C}) -> O =:= Staging andalso C end,
                          Facts))
    end).

%% One transfer for the whole run, in `persistent_term' because each eunit test
%% runs in a process of its own and the file has to outlive whichever one asked
%% for it first.
transfer() ->
    case persistent_term:get({?MODULE, transfer}, undefined) of
        undefined ->
            Transferred = fetch(),
            persistent_term:put({?MODULE, transfer}, Transferred),
            Transferred;
        Transferred ->
            Transferred
    end.

fetch() ->
    {Client, Recorder} = max_client(),
    {ok, Metadata} = vpndetection:database_metadata(Client, ?DATASET),
    ?assertEqual(?DATASET, maps:get(<<"id">>, Metadata, missing)),
    Size = published_size(Metadata),
    %% Budgeted BEFORE the transfer: a mistaken id would otherwise pull 1.79 GB
    %% through CI and the suite would still be green.
    ?assert(Size > 0 andalso Size =< ?CEILING,
            lists:flatten(io_lib:format("~s is ~b bytes, past the ~b ceiling",
                                        [?DATASET, Size, ?CEILING]))),

    Path = scratch(),
    {ok, Written} = vpndetection:database_download(Client, ?DATASET, ?FORMAT, Path),
    %% Read AFTER the transfer, so a rebuild between the two calls shows up as a
    %% digest mismatch rather than passing against a digest of nothing.
    {ok, Sums} = vpndetection:database_checksums(Client, ?DATASET, ?FORMAT),
    io:format("~s.~s: ~b bytes, metadata says ~b~n", [?DATASET, ?FORMAT, Written, Size]),
    Facts = staging_recorder:facts(Recorder),
    done(Client, Recorder),
    #{written => Written, path => Path, checksums => Sums, facts => Facts}.

published_size(Metadata) ->
    Sizes = maps:get(<<"size">>, Metadata, #{}),
    Format = atom_to_binary(?FORMAT),
    ?assert(maps:is_key(Format, Sizes),
            lists:flatten(io_lib:format("~s publishes no ~s size to check a transfer against",
                                        [?DATASET, Format]))),
    maps:get(Format, Sizes).

%% Every test in this module needs the max key, so an absent one is reported once
%% per test rather than passing as if the tier had been exercised.
max_test(Body) ->
    {timeout, 300, fun() ->
        case staging_tiers:skip_reason(staging_tiers:max()) of
            undefined -> Body();
            Reason -> staging_tiers:notice("SKIPPED: " ++ Reason)
        end
    end}.

max_client() ->
    staging_fixtures:client(staging_tiers:max()).

done(Client, Recorder) ->
    vpndetection:close(Client),
    staging_recorder:stop(Recorder).

digest(Body) ->
    Hex = [io_lib:format("~2.16.0b", [B]) || <<B>> <= crypto:hash(sha256, Body)],
    iolist_to_binary(Hex).

file_size(Path) ->
    case file:read_file_info(Path) of
        {ok, Info} -> {ok, element(2, Info)};
        Error -> Error
    end.

scratch() ->
    Dir = list_to_binary(os:getenv("TMPDIR", "/tmp")),
    Unique = integer_to_binary(erlang:unique_integer([positive])),
    <<Dir/binary, "/vpndetection-integration-", Unique/binary, "-", ?DATASET/binary, ".csv.gz">>.
