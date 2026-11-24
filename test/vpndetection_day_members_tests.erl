%% The bot, service and BitTorrent details' `first_seen' and `last_seen' are
%% days (`format: date' from spec 2026.11.23), read as every other date member
%% is: a well-formed one as served, anything else an answer the call cannot
%% read. Through 3.18.0 each was any string.
-module(vpndetection_day_members_tests).

-include_lib("eunit/include/eunit.hrl").

%% A well-formed answer carrying every one of the twelve, each day distinct so a
%% replacement lands on exactly one member.
-define(ANSWER, <<"{\"ip\":\"45.83.91.1\",\"is_vpn\":false,\"is_bot\":true,\"is_ssh\":true,\"is_smtp\":true,"
    "\"is_web\":true,\"is_dns_resolver\":true,\"is_bittorrent\":true,"
    "\"bot\":{\"provider\":\"google\",\"provider_name\":\"Google\",\"agents\":[\"Googlebot\"],"
    "\"categories\":[\"search_engine\"],\"verified\":true,\"identity\":\"verified\",\"verified_by\":\"list\","
    "\"confidence\":\"high\",\"first_seen\":\"2026-01-01\",\"last_seen\":\"2026-01-02\"},"
    "\"ssh\":{\"port\":22,\"banner\":\"SSH-2.0\",\"host_key_fp\":\"f\",\"session_ok\":true,"
    "\"first_seen\":\"2026-02-01\",\"last_seen\":\"2026-02-02\"},"
    "\"smtp\":{\"port\":25,\"banner\":\"220\",\"session_ok\":true,"
    "\"first_seen\":\"2026-03-01\",\"last_seen\":\"2026-03-02\"},"
    "\"web\":[{\"port\":443,\"tls_ok\":true,\"session_ok\":true,\"status_code\":200,\"server\":\"s\","
    "\"location\":\"\",\"title\":\"t\",\"cert_subject_cn\":\"c\",\"cert_subject_o\":\"o\",\"cert_issuer_dn\":\"i\","
    "\"cert_browser_trusted\":true,\"tls_version\":\"TLS 1.3\","
    "\"first_seen\":\"2026-04-01\",\"last_seen\":\"2026-04-02\"}],"
    "\"dns_resolver\":{\"port\":53,\"recursion_available\":true,\"rcode\":0,\"answer_correct\":true,"
    "\"first_seen\":\"2026-05-01\",\"last_seen\":\"2026-05-02\"},"
    "\"bittorrent\":{\"verified\":true,\"id_matches_ip\":true,\"first_seen\":\"2026-06-01\","
    "\"last_seen\":\"2026-06-02\",\"last_reachable\":\"\",\"days_seen\":3,\"num_ports\":1,"
    "\"peak_num_ports\":1,\"indexer\":false,\"clients\":[]}}">>).

%% Each member, by the day it holds in ?ANSWER.
-define(MEMBERS, [{"bot.first_seen", <<"2026-01-01">>}, {"bot.last_seen", <<"2026-01-02">>},
                  {"ssh.first_seen", <<"2026-02-01">>}, {"ssh.last_seen", <<"2026-02-02">>},
                  {"smtp.first_seen", <<"2026-03-01">>}, {"smtp.last_seen", <<"2026-03-02">>},
                  {"web.0.first_seen", <<"2026-04-01">>}, {"web.0.last_seen", <<"2026-04-02">>},
                  {"dns_resolver.first_seen", <<"2026-05-01">>}, {"dns_resolver.last_seen", <<"2026-05-02">>},
                  {"bittorrent.first_seen", <<"2026-06-01">>}, {"bittorrent.last_seen", <<"2026-06-02">>}]).

%% The date probe on `ssh.first_seen', after the same harness reads the answer
%% it was cut from.
the_date_probe_on_a_day_member_test_() ->
    Probe = [<<"x">>, <<"tomorrow">>, <<"monday">>, <<"2026-02-30">>, <<"24:00">>, <<"2026-02-01T24:00">>,
             <<"2026-02-01T10:00:00Z">>, <<"2026-02-01 10:00">>, <<"2026-02-01+05">>, <<"2026-02-01\n">>,
             <<"2026-2-01">>, <<"2026-02-01Z">>,
             %% An Arabic-Indic two in the year, U+0662.
             <<"20", 16#D9, 16#A2, "6-02-01">>, <<"202", 16#D9, 16#A6, "-02-01">>],
    [{"reads the well-formed answer", fun() ->
        {ok, Result} = served(?ANSWER),
        ?assertMatch(#{ssh := #{first_seen := <<"2026-02-01">>, last_seen := <<"2026-02-02">>}}, Result),
        ?assertMatch(#{web := [#{first_seen := <<"2026-04-01">>}]}, Result),
        ?assertMatch(#{bittorrent := #{last_reachable := <<>>}}, Result)
     end}
     | [{lists:flatten("ssh.first_seen " ++ io_lib:format("~p", [Bad])), fun() ->
            assert_unreadable(replace(<<"2026-02-01">>, Bad))
        end} || Bad <- Probe]].

%% Every one of the twelve refuses a value that is no day.
each_day_member_refuses_a_value_that_is_no_day_test_() ->
    [{Member, fun() -> assert_unreadable(replace(Day, <<"x">>)) end} || {Member, Day} <- ?MEMBERS].

%% The same answer as a batch entry is that address's error alone.
a_batch_entry_with_a_malformed_day_fails_that_address_alone_test() ->
    Bad = replace(<<"2026-06-02">>, <<"tomorrow">>),
    Body = <<"{\"results\":{\"45.83.91.1\":", Bad/binary, ",\"45.83.91.2\":",
             (binary:replace(?ANSWER, <<"45.83.91.1">>, <<"45.83.91.2">>))/binary, "}}">>,
    Http = fun(_) -> {ok, #{status => 200, headers => [], body => Body}} end,
    Client = vpndetection:new(#{api_key => <<"k">>, retries => 0, http => Http, cache => false}),
    Answers = vpndetection:lookup_batch(Client, [<<"45.83.91.1">>, <<"45.83.91.2">>]),
    ?assertMatch({error, #{kind := server_error, status := 200}}, maps:get(<<"45.83.91.1">>, Answers)),
    ?assertMatch({ok, #{bittorrent := #{last_seen := <<"2026-06-02">>}}}, maps:get(<<"45.83.91.2">>, Answers)).

replace(Day, With) ->
    Quoted = <<"\"", Day/binary, "\"">>,
    Escaped = iolist_to_binary(json:encode(With)),
    Body = binary:replace(?ANSWER, Quoted, Escaped),
    ?assertNotEqual(?ANSWER, Body),
    Body.

served(Body) ->
    Http = fun(_) -> {ok, #{status => 200, headers => [], body => Body}} end,
    Client = vpndetection:new(#{api_key => <<"k">>, retries => 0, http => Http, cache => false}),
    vpndetection:lookup(Client, <<"45.83.91.1">>).

%% Retried as any unreadable answer is, and carrying its status.
assert_unreadable(Body) ->
    Sent = counters:new(1, []),
    Http = fun(_) ->
        counters:add(Sent, 1, 1),
        {ok, #{status => 200, headers => [], body => Body}}
    end,
    Client = vpndetection:new(#{api_key => <<"k">>, retries => 1, http => Http, cache => false}),
    ?assertMatch({error, #{kind := server_error, retryable := true, status := 200}},
                 vpndetection:lookup(Client, <<"45.83.91.1">>)),
    ?assertEqual(2, counters:get(Sent, 1)).
