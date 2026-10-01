%% @doc The per-client result cache: an LRU with a TTL, owned by one process.
%%
%% An ETS table dies with the process that created it, so a cache that is meant
%% to outlive the code building the client needs an owner of its own. That owner
%% is also the serialization point the LRU needs, because recency is kept in a
%% second table that has to stay in step with the first.
%%
%% Reads do NOT go through it. `get/2' reads the entry table directly, so the N
%% workers of a batch never queue behind one process to find out they have a hit.
%%
%% The owner also keeps the board of requests in the air, so concurrent misses
%% for one address share one request. A caller that misses boards the address:
%% the first to do so leads and sends it, every later one waits, and the leader
%% lands the answer, which caches a success and hands the answer to each waiter
%% in one step. A leader that dies before it lands sends its waiters back to ask
%% again rather than failing them with it.
-module(vpndetection_cache).
-behaviour(gen_server).

-export([start_link/2, stop/1, get/2, put/3]).
-export([board/3, land/2, abandon/2, await/3]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-export_type([cache/0, outcome/0]).

-type cache() :: #{pid := pid(), entries := ets:table()}.
-type answer() :: {ok, vpndetection_result:result()} | {error, vpndetection_error:error()}.
%% What a waiter hears: the leader's answer, or `retry' when the leader died first.
-type outcome() :: answer() | retry.

-define(FLIGHT_TAG, '$vpndetection_flight').

-record(state, {entries :: ets:table(), order :: ets:table(), max :: pos_integer(),
                ttl_ms :: pos_integer(), seq = 0 :: non_neg_integer(),
                %% Each address in the air: who leads it, and who awaits it under which ref.
                flights = #{} :: #{binary() => {pid(), [{pid(), reference()}]}},
                %% Each leader's monitor and the addresses it leads.
                leaders = #{} :: #{pid() => {reference(), #{binary() => true}}}}).

%% @doc Start a cache holding at most `Max' addresses for `TtlMs' each.
%%
%% Linked, so a cache cannot outlive the process that built the client and leak
%% a process plus two ETS tables that nothing will ever collect. Build clients
%% in something long lived, and call `vpndetection:close/1' when done.
-spec start_link(pos_integer(), pos_integer()) -> {ok, cache()}.
start_link(Max, TtlMs) ->
    {ok, Pid} = gen_server:start_link(?MODULE, {Max, TtlMs}, []),
    Entries = gen_server:call(Pid, entries),
    {ok, #{pid => Pid, entries => Entries}}.

-spec stop(cache()) -> ok.
stop(#{pid := Pid}) ->
    gen_server:stop(Pid).

%% @doc Read an address, if it is held and still fresh.
%%
%% A cache whose owner has gone answers `miss' rather than raising: a miss is
%% always safe, and taking a caller's request path down because an optimization
%% went away would not be.
-spec get(cache(), binary()) -> {ok, vpndetection_result:result()} | miss.
get(#{pid := Pid, entries := Entries}, Ip) ->
    try ets:lookup(Entries, Ip) of
        [{Ip, Result, ExpiresAt, _Seq}] ->
            case erlang:monotonic_time(millisecond) < ExpiresAt of
                true -> gen_server:cast(Pid, {touch, Ip}), {ok, Result};
                false -> gen_server:cast(Pid, {drop, Ip}), miss
            end;
        [] ->
            miss
    catch
        error:badarg -> miss
    end.

-spec put(cache(), binary(), vpndetection_result:result()) -> ok.
put(#{pid := Pid}, Ip, Result) ->
    try
        gen_server:call(Pid, {put, Ip, Result})
    catch
        exit:_ -> ok
    end.

%% @doc Board addresses that missed: each is a fresh answer, `lead' (send it,
%% then {@link land/2} it) or `wait' ({@link await/3} it under `Ref').
%%
%% The cache is read again here, under the owner, because a request that lands
%% caches its answer in the same step it leaves the board: a miss here with no
%% flight means nobody is in the air. A cache whose owner has gone answers
%% `lead' for every address, and the caller sends them all itself.
-spec board(cache(), [binary()], reference()) ->
    [{binary(), {ok, vpndetection_result:result()} | lead | wait}].
board(#{pid := Pid}, Ips, Ref) ->
    try
        gen_server:call(Pid, {board, Ips, Ref}, infinity)
    catch
        exit:_ -> [{Ip, lead} || Ip <- Ips]
    end.

%% @doc Land the answers to addresses the caller leads. A success is cached, and
%% every answer reaches the address's waiters; an error is cached for none.
-spec land(cache(), [{binary(), answer()}]) -> ok.
land(#{pid := Pid}, Answers) ->
    try
        gen_server:call(Pid, {land, Answers}, infinity)
    catch
        exit:_ -> ok
    end.

%% @doc Take addresses the caller leads off the board without an answer, sending
%% their waiters back to ask again: for a leader that failed before it had one.
-spec abandon(cache(), [binary()]) -> ok.
abandon(#{pid := Pid}, Ips) ->
    try
        gen_server:call(Pid, {abandon, Ips}, infinity)
    catch
        exit:_ -> ok
    end.

%% @doc Wait for the addresses boarded as `wait' under `Ref'. Each answers its
%% leader's answer, or `retry' when the leader, or the cache itself, went away
%% before it landed one.
-spec await(cache(), reference(), [binary()]) -> #{binary() => outcome()}.
await(_Cache, _Ref, []) ->
    #{};
await(#{pid := Pid}, Ref, Ips) ->
    Monitor = erlang:monitor(process, Pid),
    Outcomes = await_each(Ref, Monitor, maps:from_keys(Ips, true), #{}),
    erlang:demonitor(Monitor, [flush]),
    Outcomes.

await_each(_Ref, _Monitor, Left, Acc) when map_size(Left) =:= 0 ->
    Acc;
await_each(Ref, Monitor, Left, Acc) ->
    receive
        {?FLIGHT_TAG, Ref, Ip, Outcome} when is_map_key(Ip, Left) ->
            await_each(Ref, Monitor, maps:remove(Ip, Left), Acc#{Ip => Outcome});
        {'DOWN', Monitor, process, _, _} ->
            maps:merge(Acc, maps:map(fun(_Ip, true) -> retry end, Left))
    end.

init({Max, TtlMs}) ->
    Entries = ets:new(vpndetection_cache_entries, [set, public, {read_concurrency, true}]),
    Order = ets:new(vpndetection_cache_order, [ordered_set, private]),
    {ok, #state{entries = Entries, order = Order, max = Max, ttl_ms = TtlMs}}.

handle_call(entries, _From, State) ->
    {reply, State#state.entries, State};
handle_call({put, Ip, Result}, _From, State) ->
    {reply, ok, insert(State, Ip, Result)};
handle_call({board, Ips, Ref}, {Caller, _Tag}, State) ->
    {Boarded, Next} = lists:mapfoldl(fun(Ip, S) -> board_one(S, Ip, Caller, Ref) end, State, Ips),
    {reply, Boarded, Next};
handle_call({land, Answers}, {Caller, _Tag}, State) ->
    {reply, ok, lists:foldl(fun({Ip, Answer}, S) -> land_one(S, Ip, Answer, Caller) end,
                            State, Answers)};
handle_call({abandon, Ips}, {Caller, _Tag}, State) ->
    {reply, ok, lists:foldl(fun(Ip, S) -> release(S, Ip, Caller) end, State, Ips)}.

handle_cast({touch, Ip}, State) ->
    {noreply, touch(State, Ip)};
handle_cast({drop, Ip}, State) ->
    forget_order(State, Ip),
    ets:delete(State#state.entries, Ip),
    {noreply, State}.

%% A leader that died mid-request lands nothing, so its waiters ask again.
handle_info({'DOWN', _Monitor, process, Pid, _Reason}, State) ->
    case State#state.leaders of
        #{Pid := {_, Ips}} ->
            {noreply, lists:foldl(fun(Ip, S) -> release(S, Ip, Pid) end, State, maps:keys(Ips))};
        #{} ->
            {noreply, State}
    end;
handle_info(_Message, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

board_one(State = #state{flights = Flights}, Ip, Caller, Ref) ->
    case fresh(State, Ip) of
        {ok, Result} ->
            {{Ip, {ok, Result}}, touch(State, Ip)};
        miss ->
            case Flights of
                #{Ip := {Leader, Waiters}} ->
                    Flight = {Leader, [{Caller, Ref} | Waiters]},
                    {{Ip, wait}, State#state{flights = Flights#{Ip := Flight}}};
                #{} ->
                    {{Ip, lead}, lead(State, Ip, Caller)}
            end
    end.

lead(State = #state{flights = Flights, leaders = Leaders}, Ip, Caller) ->
    Led = case Leaders of
        #{Caller := {Monitor, Ips}} -> {Monitor, Ips#{Ip => true}};
        #{} -> {erlang:monitor(process, Caller), #{Ip => true}}
    end,
    State#state{flights = Flights#{Ip => {Caller, []}}, leaders = Leaders#{Caller => Led}}.

%% Cached before it leaves the board, in the same step, which is what lets
%% board_one/4 read a miss with no flight as nobody in the air.
land_one(State0, Ip, Answer, Caller) ->
    State = case Answer of
        {ok, Result} -> insert(State0, Ip, Result);
        {error, _} -> State0
    end,
    case State#state.flights of
        #{Ip := {Caller, Waiters}} ->
            notify(Waiters, Ip, Answer),
            unboard(State, Ip, Caller);
        #{} ->
            State
    end.

release(State, Ip, Caller) ->
    case State#state.flights of
        #{Ip := {Caller, Waiters}} ->
            notify(Waiters, Ip, retry),
            unboard(State, Ip, Caller);
        #{} ->
            State
    end.

notify(Waiters, Ip, Outcome) ->
    _ = [Waiter ! {?FLIGHT_TAG, Ref, Ip, Outcome} || {Waiter, Ref} <- Waiters],
    ok.

unboard(State = #state{flights = Flights, leaders = Leaders}, Ip, Caller) ->
    Next = case Leaders of
        #{Caller := {Monitor, Ips}} when map_size(Ips) =:= 1 ->
            erlang:demonitor(Monitor, [flush]),
            maps:remove(Caller, Leaders);
        #{Caller := {Monitor, Ips}} ->
            Leaders#{Caller := {Monitor, maps:remove(Ip, Ips)}};
        #{} ->
            Leaders
    end,
    State#state{flights = maps:remove(Ip, Flights), leaders = Next}.

fresh(State, Ip) ->
    case ets:lookup(State#state.entries, Ip) of
        [{Ip, Result, ExpiresAt, _Seq}] ->
            case erlang:monotonic_time(millisecond) < ExpiresAt of
                true -> {ok, Result};
                false -> miss
            end;
        [] ->
            miss
    end.

insert(State, Ip, Result) ->
    Seq = State#state.seq + 1,
    forget_order(State, Ip),
    ExpiresAt = erlang:monotonic_time(millisecond) + State#state.ttl_ms,
    ets:insert(State#state.entries, {Ip, Result, ExpiresAt, Seq}),
    ets:insert(State#state.order, {Seq, Ip}),
    evict(State),
    State#state{seq = Seq}.

touch(State, Ip) ->
    Seq = State#state.seq + 1,
    case ets:lookup(State#state.entries, Ip) of
        [{Ip, Result, ExpiresAt, Old}] ->
            ets:delete(State#state.order, Old),
            ets:insert(State#state.entries, {Ip, Result, ExpiresAt, Seq}),
            ets:insert(State#state.order, {Seq, Ip}),
            State#state{seq = Seq};
        [] ->
            State
    end.

forget_order(State, Ip) ->
    case ets:lookup(State#state.entries, Ip) of
        [{Ip, _Result, _ExpiresAt, Old}] -> ets:delete(State#state.order, Old);
        [] -> ok
    end.

%% The lowest sequence number in an ordered_set is the least recently used entry,
%% so eviction is a first-key read rather than a scan of the whole table.
evict(State) ->
    case ets:info(State#state.entries, size) > State#state.max of
        true ->
            Oldest = ets:first(State#state.order),
            [{Oldest, Ip}] = ets:lookup(State#state.order, Oldest),
            ets:delete(State#state.order, Oldest),
            ets:delete(State#state.entries, Ip),
            evict(State);
        false ->
            ok
    end.
