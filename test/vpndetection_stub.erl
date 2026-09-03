%% An HTTP stand-in that answers from a table and counts what it was asked for,
%% so "never touched the network" is asserted rather than assumed.
%%
%% It answers from a process and delays in a child, so several requests really do
%% overlap and the PEAK number in flight is a measurement rather than a guess.
-module(vpndetection_stub).

-export([start/1, start/2, stop/1, http/1, calls/1, peak/1, request/2]).

%% @doc `Routes' is keyed by the request path, with or without its leading slash,
%% and percent decoded. A path with no route answers 400, which is what the API
%% does for an address it cannot parse.
start(Routes) ->
    start(Routes, 0).

start(Routes, DelayMs) ->
    spawn_link(fun() ->
        loop(#{routes => Routes, delay => DelayMs, calls => 0, in_flight => 0, peak => 0})
    end).

stop(Pid) ->
    ask(Pid, stop).

http(Pid) ->
    fun(#{url := Url}) -> ?MODULE:request(Pid, Url) end.

calls(Pid) ->
    ask(Pid, {stat, calls}).

peak(Pid) ->
    ask(Pid, {stat, peak}).

request(Pid, Url) ->
    Ref = make_ref(),
    Pid ! {request, self(), Ref, Url},
    receive
        {Ref, Response} -> Response
    after 15000 ->
        {error, stub_timeout}
    end.

loop(#{calls := Calls, in_flight := InFlight, peak := Peak} = State) ->
    receive
        {request, From, Ref, Url} ->
            Self = self(),
            Response = respond(maps:get(routes, State), Url),
            Delay = maps:get(delay, State),
            spawn(fun() ->
                timer:sleep(Delay),
                From ! {Ref, Response},
                Self ! released
            end),
            loop(State#{calls := Calls + 1, in_flight := InFlight + 1,
                        peak := max(Peak, InFlight + 1)});
        released ->
            loop(State#{in_flight := InFlight - 1});
        {{stat, Key}, From, Ref} ->
            From ! {Ref, maps:get(Key, State)},
            loop(State);
        {stop, From, Ref} ->
            From ! {Ref, ok}
    end.

respond(Routes, Url) ->
    Path = path_of(Url),
    Route = case {maps:find(Path, Routes), maps:find(strip(Path), Routes)} of
        {{ok, R}, _} -> R;
        {_, {ok, R}} -> R;
        _ -> #{status => 400, body => #{<<"error">> => <<"not a valid IP address">>}}
    end,
    Headers = maps:get(headers, Route, #{}),
    {ok, #{
        status => maps:get(status, Route, 200),
        %% The real transport lowercases header names, so this one does too; a
        %% stub that handed back `Retry-After' would let a case-sensitive lookup
        %% pass here and fail against the API.
        headers => [{<<"content-type">>, <<"application/json">>}
                    | [{lower(K), V} || {K, V} <- maps:to_list(Headers)]],
        body => iolist_to_binary(json:encode(maps:get(body, Route, #{})))
    }}.

path_of(Url) ->
    #{path := Path} = uri_string:parse(Url),
    uri_string:percent_decode(Path).

strip(<<"/", Rest/binary>>) -> Rest;
strip(Path) -> Path.

lower(Name) -> list_to_binary(string:lowercase(binary_to_list(Name))).

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(stub_unresponsive)
    end.
