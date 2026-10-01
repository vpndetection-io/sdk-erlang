%% Concurrent misses for one address share one request, a lookup's or the batch
%% chunk carrying it, every other caller awaiting it. The origin holds each
%% request until the test opens it, and each test waits until every waiter is
%% parked on the board, so the calls under test are known to overlap rather than
%% hoped to.
-module(vpndetection_shared_lookup_tests).

-include_lib("eunit/include/eunit.hrl").

-define(VISITOR, <<"8.8.8.8">>).
-define(OTHER, <<"1.1.1.1">>).
-define(FAILING, <<"9.9.9.9">>).

concurrent_lookups_of_one_address_share_one_request_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Callers = [spawn_lookup(Client, ?VISITOR) || _ <- lists:seq(1, 20)],

        wait_until(fun() -> arrived(Gate) =:= 1 andalso length(parked(Callers)) =:= 19 end),
        open(Gate),

        [?assertMatch({ok, #{ip := ?VISITOR}}, answer(Caller)) || Caller <- Callers],
        ?assertEqual(1, arrived(Gate)),
        ?assertMatch({ok, #{ip := ?VISITOR}}, vpndetection:lookup(Client, ?VISITOR)),
        ?assertEqual(1, arrived(Gate)),
        teardown(Gate, Client)
    end}.

a_batch_awaits_a_lookup_already_in_flight_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Lookup = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> arrived(Gate) =:= 1 end),

        Batch = spawn_batch(Client, [?VISITOR, ?OTHER]),
        wait_until(fun() -> arrived(Gate) =:= 2 end),
        open(Gate),

        ?assertMatch({ok, #{ip := ?VISITOR}}, answer(Lookup)),
        Answers = answer(Batch),
        ?assertMatch({ok, #{ip := ?VISITOR}}, maps:get(?VISITOR, Answers)),
        ?assertMatch({ok, #{ip := ?OTHER}}, maps:get(?OTHER, Answers)),
        %% The batch sent only the address nobody had in the air.
        ?assertEqual([[?OTHER]], batch_bodies(Gate)),
        ?assertEqual(2, arrived(Gate)),
        teardown(Gate, Client)
    end}.

a_lookup_awaits_the_batch_chunk_carrying_its_address_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Batch = spawn_batch(Client, [?VISITOR, ?OTHER]),
        wait_until(fun() -> arrived(Gate) =:= 1 end),

        Lookup = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> parked([Lookup]) =:= [Lookup] end),
        open(Gate),

        ?assertMatch({ok, #{ip := ?VISITOR}}, answer(Lookup)),
        ?assertMatch(#{?VISITOR := {ok, _}, ?OTHER := {ok, _}}, answer(Batch)),
        ?assertEqual(1, arrived(Gate)),
        teardown(Gate, Client)
    end}.

a_failure_reaches_every_waiter_and_is_cached_for_none_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{retries => 0}),
        Callers = [spawn_lookup(Client, ?FAILING) || _ <- lists:seq(1, 5)],

        wait_until(fun() -> arrived(Gate) =:= 1 andalso length(parked(Callers)) =:= 4 end),
        open(Gate),

        [?assertMatch({error, #{kind := server_error}}, answer(Caller)) || Caller <- Callers],
        ?assertEqual(1, arrived(Gate)),
        ?assertMatch({error, #{kind := server_error}}, vpndetection:lookup(Client, ?FAILING)),
        ?assertEqual(2, arrived(Gate)),
        teardown(Gate, Client)
    end}.

a_waiter_whose_leader_was_cut_off_asks_again_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Leader = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> arrived(Gate) =:= 1 end),
        Waiter = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> parked([Waiter]) =:= [Waiter] end),

        exit(Leader, kill),

        wait_until(fun() -> arrived(Gate) =:= 2 end),
        open(Gate),
        ?assertMatch({ok, #{ip := ?VISITOR}}, answer(Waiter)),
        teardown(Gate, Client)
    end}.

a_lookup_whose_batch_was_cut_off_asks_again_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Batch = spawn_batch(Client, [?VISITOR, ?OTHER]),
        wait_until(fun() -> arrived(Gate) =:= 1 end),
        Waiter = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> parked([Waiter]) =:= [Waiter] end),

        exit(Batch, kill),

        wait_until(fun() -> arrived(Gate) =:= 2 end),
        open(Gate),
        ?assertMatch({ok, #{ip := ?VISITOR}}, answer(Waiter)),
        teardown(Gate, Client)
    end}.

a_batch_whose_lookup_was_cut_off_asks_again_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Lookup = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> arrived(Gate) =:= 1 end),
        Batch = spawn_batch(Client, [?VISITOR, ?OTHER]),
        wait_until(fun() -> arrived(Gate) =:= 2 end),

        exit(Lookup, kill),
        open(Gate),

        ?assertMatch(#{?VISITOR := {ok, #{ip := ?VISITOR}}, ?OTHER := {ok, _}}, answer(Batch)),
        ?assertEqual([[?OTHER], [?VISITOR]], batch_bodies(Gate)),
        teardown(Gate, Client)
    end}.

%% A leader whose request raises, in a caller that catches it and lives on,
%% still frees its waiters: no process went down to tell the board.
a_waiter_whose_leader_raised_asks_again_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{}),
        Leader = caller(fun() -> vpndetection:lookup(Client, ?VISITOR) end, linger),
        wait_until(fun() -> arrived(Gate) =:= 1 end),
        Waiter = spawn_lookup(Client, ?VISITOR),
        wait_until(fun() -> parked([Waiter]) =:= [Waiter] end),

        raise(Gate),
        ?assertMatch({raised, error, origin_raised}, answer(Leader)),

        wait_until(fun() -> arrived(Gate) =:= 2 end),
        open(Gate),
        ?assertMatch({ok, #{ip := ?VISITOR}}, answer(Waiter)),
        ?assert(is_process_alive(Leader)),
        Leader ! stop,
        teardown(Gate, Client)
    end}.

without_a_cache_nothing_is_shared_test_() ->
    {timeout, 30, fun() ->
        {Gate, Client} = setup(#{cache => false}),
        Callers = [spawn_lookup(Client, ?VISITOR) || _ <- lists:seq(1, 5)],

        wait_until(fun() -> arrived(Gate) =:= 5 end),
        open(Gate),

        [?assertMatch({ok, #{ip := ?VISITOR}}, answer(Caller)) || Caller <- Callers],
        ?assertEqual(5, arrived(Gate)),
        teardown(Gate, Client)
    end}.

%% The board reads the cache again under its owner, so a caller that missed just
%% before a leader landed takes the answer rather than sending a second request.
boarding_an_address_already_cached_answers_it_test() ->
    {ok, Cache} = vpndetection_cache:start_link(10, 60000),
    Result = #{ip => ?VISITOR, is_vpn => false},
    ok = vpndetection_cache:put(Cache, ?VISITOR, Result),

    ?assertEqual([{?VISITOR, {ok, Result}}, {?OTHER, lead}],
                 vpndetection_cache:board(Cache, [?VISITOR, ?OTHER], make_ref())),
    vpndetection_cache:stop(Cache).

setup(Options) ->
    Stub = vpndetection_stub:start(#{
        ?VISITOR => #{body => #{<<"ip">> => ?VISITOR, <<"is_vpn">> => false}},
        ?OTHER => #{body => #{<<"ip">> => ?OTHER, <<"is_vpn">> => false}},
        ?FAILING => #{status => 500, body => #{<<"error">> => <<"lookup failed">>}}
    }),
    Gate = spawn_link(fun() -> gate(#{stub => Stub, held => [], arrived => [], mode => held}) end),
    Http = fun(Request) -> through(Gate, Request) end,
    {Gate, vpndetection:new(Options#{http => Http})}.

teardown(Gate, Client) ->
    vpndetection:close(Client),
    ask(Gate, stop).

%% Each caller runs in its own process and posts its answer to the test.
spawn_lookup(Client, Ip) ->
    caller(fun() -> vpndetection:lookup(Client, Ip) end).

spawn_batch(Client, Ips) ->
    caller(fun() -> vpndetection:lookup_batch(Client, Ips) end).

caller(Call) ->
    caller(Call, leave).

%% `linger' keeps the caller alive after it answers, until it is sent `stop'.
caller(Call, Then) ->
    Test = self(),
    spawn(fun() ->
        Answer = try Call() catch Class:Reason -> {raised, Class, Reason} end,
        Test ! {answer, self(), Answer},
        case Then of
            linger -> receive stop -> ok end;
            leave -> ok
        end
    end).

answer(Caller) ->
    receive
        {answer, Caller, Answer} -> Answer
    after 10000 ->
        error({no_answer_from, Caller})
    end.

%% The callers parked on the board, awaiting another's request.
parked(Callers) ->
    [Caller || Caller <- Callers,
               erlang:process_info(Caller, current_function) =:=
                   {current_function, {vpndetection_cache, await_each, 4}}].

wait_until(Check) ->
    wait_until(Check, 1000).

wait_until(Check, 0) ->
    ?assert(Check());
wait_until(Check, Tries) ->
    case Check() of
        true -> ok;
        false -> timer:sleep(5), wait_until(Check, Tries - 1)
    end.

arrived(Gate) ->
    length(ask(Gate, arrived)).

%% The addresses each POST /batch carried, in arrival order.
batch_bodies(Gate) ->
    [maps:get(<<"ips">>, json:decode(Body)) || {Url, Body} <- ask(Gate, arrived),
                                               binary:match(Url, <<"/batch">>) =/= nomatch].

open(Gate) ->
    ask(Gate, open).

raise(Gate) ->
    ask(Gate, raise).

%% A request reaches the stub only once the gate lets it through; `raise' lets
%% the held ones through as an exception instead, as a transport bug would.
through(Gate, #{url := Url} = Request) ->
    Ref = make_ref(),
    Gate ! {arrive, self(), Ref, Url, maps:get(body, Request, <<>>)},
    receive
        {Ref, go, Stub} -> vpndetection_stub:request(Stub, Request);
        {Ref, raise, _Stub} -> error(origin_raised)
    end.

gate(#{stub := Stub, held := Held, arrived := Arrived, mode := Mode} = State) ->
    receive
        {arrive, From, Ref, Url, Body} ->
            Next = State#{arrived := Arrived ++ [{Url, Body}]},
            case Mode of
                held -> gate(Next#{held := [{From, Ref} | Held]});
                open -> From ! {Ref, go, Stub}, gate(Next)
            end;
        {open, From, Ref} ->
            _ = [Caller ! {CallRef, go, Stub} || {Caller, CallRef} <- Held],
            From ! {Ref, ok},
            gate(State#{held := [], mode := open});
        {raise, From, Ref} ->
            _ = [Caller ! {CallRef, raise, Stub} || {Caller, CallRef} <- Held],
            From ! {Ref, ok},
            gate(State#{held := []});
        {arrived, From, Ref} ->
            From ! {Ref, Arrived},
            gate(State);
        {stop, From, Ref} ->
            vpndetection_stub:stop(Stub),
            From ! {Ref, ok}
    end.

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(gate_unresponsive)
    end.
