%% The licensed-download half: the 302 to object storage, the streamed transfer,
%% and every way one can fail.
%%
%% These run against a real socket rather than a stubbed transport, because the
%% claims are about the transport itself: that httpc hands a body over in pieces,
%% that a body cut short of its declared length fails rather than producing a
%% short file, and that the credential stops at the API.
-module(vpndetection_download_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DOWNLOAD_PATH, <<"/api/v1/database/download">>).

a_dataset_is_streamed_to_disk_whole_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("dataset.csv.gz"),

        {ok, Written} = vpndetection:database_download(Client, <<"dataset">>, csvgz, Path),

        Payload = vpndetection_origin:payload(),
        ?assertEqual(byte_size(Payload), Written),
        ?assertEqual({ok, Payload}, file:read_file(Path)),
        %% The bytes are in the file the caller named, and the working file it was
        %% assembled in is gone.
        ?assertEqual(false, filelib:is_file(<<Path/binary, ".part">>)),
        done(Origin, Client, Path)
    end}.

the_bytes_variant_agrees_with_the_streamed_copy_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("agreement.csv.gz"),

        {ok, Written} = vpndetection:database_download(Client, <<"dataset">>, csvgz, Path),
        {ok, Bytes} = vpndetection:database_download_bytes(Client, <<"dataset">>, csvgz),

        {ok, Streamed} = file:read_file(Path),
        ?assertEqual(byte_size(Streamed), byte_size(Bytes)),
        %% Byte for byte, not merely the same length: the two share a transfer
        %% path precisely so they cannot drift into disagreeing.
        ?assertEqual(Streamed, Bytes),
        ?assertEqual(Written, byte_size(Bytes)),
        done(Origin, Client, Path)
    end}.

%% The presigned link authorizes itself. Forwarding the API key would hand a
%% credential to a host with no business holding it, and the mistake is invisible
%% from the client side because the transfer succeeds either way.
no_credential_is_sent_to_object_storage_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("credential.csv.gz"),

        {ok, _} = vpndetection:database_download(Client, <<"dataset">>, csvgz, Path),

        ?assertEqual(1, vpndetection_origin:hits(Origin, ?DOWNLOAD_PATH)),
        ?assert(vpndetection_origin:authorized(Origin, ?DOWNLOAD_PATH)),
        ?assertEqual(1, vpndetection_origin:hits(Origin, <<"/dataset">>)),
        ?assertNot(vpndetection_origin:authorized(Origin, <<"/dataset">>)),
        done(Origin, Client, Path)
    end}.

%% A body that stops short of its declared content-length is the failure that
%% costs the most when it is silent: the file looks like a dataset, parses as a
%% dataset, and is missing rows nobody asked about.
a_truncated_transfer_fails_and_leaves_nothing_behind_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("truncated.csv.gz"),

        Result = vpndetection:database_download(Client, <<"truncated">>, csvgz, Path),

        ?assertMatch({error, #{kind := network, retryable := false}}, Result),
        {error, #{message := Message}} = Result,
        ?assertNotEqual(nomatch, binary:match(Message, <<"the transfer failed after">>)),
        ?assertEqual(false, filelib:is_file(Path)),
        ?assertEqual(false, filelib:is_file(<<Path/binary, ".part">>)),
        done(Origin, Client, Path)
    end}.

%% Once bytes have reached the sink a retry would append a second copy of the
%% body to them, so the failure is deliberately not retryable however transient
%% its cause looks.
a_transfer_that_broke_partway_is_not_retried_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("no-retry.csv.gz"),

        {error, _} = vpndetection:database_download(Client, <<"truncated">>, csvgz, Path),

        %% Retries are 3 on this client, and none of them was spent.
        ?assertEqual(1, vpndetection_origin:hits(Origin, <<"/truncated">>)),
        done(Origin, Client, Path)
    end}.

a_refused_link_leaves_no_partial_file_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("expired.csv.gz"),

        Result = vpndetection:database_download(Client, <<"expired">>, csvgz, Path),

        ?assertMatch({error, #{kind := forbidden, status := 403, retryable := false}}, Result),
        {error, #{message := Message}} = Result,
        ?assertNotEqual(nomatch, binary:match(Message, <<"object storage refused">>)),
        ?assertEqual(false, filelib:is_file(Path)),
        ?assertEqual(false, filelib:is_file(<<Path/binary, ".part">>)),
        done(Origin, Client, Path)
    end}.

%% A dataset the organization holds no licence for. The API says which refusal it
%% is in `rc', and reading it is what separates "not licensed" from "your term
%% lapsed" without a support ticket.
an_unlicensed_dataset_is_refused_once_carrying_the_api_rc_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("unlicensed.csv.gz"),

        Result = vpndetection:database_download(Client, <<"unlicensed">>, csvgz, Path),

        ?assertEqual({error, #{kind => forbidden, status => 403, retryable => false,
                               message => <<"NOT_LICENSED">>}}, Result),
        %% Retries are 3 on this client. A 4xx is a client error, so trying again
        %% cannot change the answer and must not be attempted.
        ?assertEqual(1, vpndetection_origin:hits(Origin, ?DOWNLOAD_PATH)),
        ?assertEqual(false, filelib:is_file(<<Path/binary, ".part">>)),
        done(Origin, Client, Path)
    end}.

the_bytes_variant_refuses_the_same_way_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),

        Result = vpndetection:database_download_bytes(Client, <<"unlicensed">>, csvgz),

        ?assertMatch({error, #{kind := forbidden, status := 403, message := <<"NOT_LICENSED">>}},
                     Result),
        ?assertEqual(1, vpndetection_origin:hits(Origin, ?DOWNLOAD_PATH)),
        done(Origin, Client, undefined)
    end}.

%% Nothing bigger than a chunk is ever held, and the only honest way to say so is
%% to count what the transport hands over: a body delivered in one piece would be
%% a body httpc had already assembled in memory.
the_body_arrives_in_pieces_rather_than_whole_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Url = <<(vpndetection_origin:base_url(Origin))/binary, "/dataset">>,
        Sink = #{acc => [], fold => fun(Chunk, Sizes) -> {ok, [byte_size(Chunk) | Sizes]} end},

        {ok, #{written := Written, acc := Sizes}} =
            vpndetection_http:get_stream(Client, Url, Sink, 0),

        Payload = vpndetection_origin:payload(),
        ?assertEqual(byte_size(Payload), Written),
        ?assert(length(Sizes) > 1),
        ?assert(lists:max(Sizes) < byte_size(Payload)),
        done(Origin, Client, undefined)
    end}.

a_sink_that_refuses_the_bytes_stops_the_transfer_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Url = <<(vpndetection_origin:base_url(Origin))/binary, "/dataset">>,
        Sink = #{acc => 0, fold => fun(_Chunk, _N) -> {error, <<"the disk said no">>} end},

        Result = vpndetection_http:get_stream(Client, Url, Sink, 2),

        %% Local, so not the API's problem and not worth asking again.
        ?assertEqual({error, #{kind => io, retryable => false, message => <<"the disk said no">>}},
                     Result),
        ?assertEqual(1, vpndetection_origin:hits(Origin, <<"/dataset">>)),
        done(Origin, Client, undefined)
    end}.

%% The destination is the caller's to get right, and a directory that does not
%% exist must not cost a request or a byte of quota to discover.
an_unwritable_destination_fails_before_anything_is_requested_test_() ->
    {timeout, 60, fun() ->
        {Origin, Client} = origin(),
        Path = scratch("no-such-directory/dataset.csv.gz"),

        Result = vpndetection:database_download(Client, <<"dataset">>, csvgz, Path),

        ?assertMatch({error, #{kind := io, retryable := false}}, Result),
        ?assertEqual(0, vpndetection_origin:hits(Origin, ?DOWNLOAD_PATH)),
        done(Origin, Client, undefined)
    end}.

origin() ->
    Origin = vpndetection_origin:start(#{}),
    Client = vpndetection:new(#{base_url => vpndetection_origin:base_url(Origin),
                                api_key => <<"k">>, cache => false, retries => 3,
                                timeout_ms => 5000}),
    {Origin, Client}.

done(Origin, Client, Path) ->
    vpndetection:close(Client),
    vpndetection_origin:stop(Origin),
    case Path of
        undefined -> ok;
        _ -> _ = file:delete(Path), _ = file:delete(<<Path/binary, ".part">>), ok
    end.

scratch(Name) ->
    Dir = list_to_binary(os:getenv("TMPDIR", "/tmp")),
    Unique = integer_to_binary(erlang:unique_integer([positive])),
    <<Dir/binary, "/vpndetection-", Unique/binary, "-", (list_to_binary(Name))/binary>>.
