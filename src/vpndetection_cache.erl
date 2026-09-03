%% @doc The per-client result cache: an LRU with a TTL, owned by one process.
%%
%% An ETS table dies with the process that created it, so a cache that is meant
%% to outlive the code building the client needs an owner of its own. That owner
%% is also the serialization point the LRU needs, because recency is kept in a
%% second table that has to stay in step with the first.
%%
%% Reads do NOT go through it. `get/2' reads the entry table directly, so the N
%% workers of a batch never queue behind one process to find out they have a hit.
-module(vpndetection_cache).
-behaviour(gen_server).

-export([start_link/2, stop/1, get/2, put/3]).
-export([init/1, handle_call/3, handle_cast/2, terminate/2]).

-export_type([cache/0]).

-type cache() :: #{pid := pid(), entries := ets:table()}.

-record(state, {entries :: ets:table(), order :: ets:table(), max :: pos_integer(),
                ttl_ms :: pos_integer(), seq = 0 :: non_neg_integer()}).

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

init({Max, TtlMs}) ->
    Entries = ets:new(vpndetection_cache_entries, [set, public, {read_concurrency, true}]),
    Order = ets:new(vpndetection_cache_order, [ordered_set, private]),
    {ok, #state{entries = Entries, order = Order, max = Max, ttl_ms = TtlMs}}.

handle_call(entries, _From, State) ->
    {reply, State#state.entries, State};
handle_call({put, Ip, Result}, _From, State) ->
    Seq = State#state.seq + 1,
    forget_order(State, Ip),
    ExpiresAt = erlang:monotonic_time(millisecond) + State#state.ttl_ms,
    ets:insert(State#state.entries, {Ip, Result, ExpiresAt, Seq}),
    ets:insert(State#state.order, {Seq, Ip}),
    evict(State),
    {reply, ok, State#state{seq = Seq}}.

handle_cast({touch, Ip}, State) ->
    Seq = State#state.seq + 1,
    case ets:lookup(State#state.entries, Ip) of
        [{Ip, Result, ExpiresAt, Old}] ->
            ets:delete(State#state.order, Old),
            ets:insert(State#state.entries, {Ip, Result, ExpiresAt, Seq}),
            ets:insert(State#state.order, {Seq, Ip}),
            {noreply, State#state{seq = Seq}};
        [] ->
            {noreply, State}
    end;
handle_cast({drop, Ip}, State) ->
    forget_order(State, Ip),
    ets:delete(State#state.entries, Ip),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

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
