%% A real HTTP origin on a real socket, for the claims a stubbed transport cannot
%% make honestly: that httpc itself lets the configured number of requests run at
%% once, and that a redirect to a huge file is not followed.
-module(vpndetection_origin).

-export([start/1, stop/1, base_url/1, peak/1, hits/2]).

-define(HUGE_BYTES, 5000000000).

start(Options) ->
    Parent = self(),
    Pid = spawn_link(fun() -> boot(Parent, Options) end),
    receive
        {?MODULE, Pid, ready} -> Pid
    after 5000 ->
        error(origin_did_not_start)
    end.

stop(Pid) ->
    ask(Pid, stop).

base_url(Pid) ->
    Port = ask(Pid, port),
    iolist_to_binary(io_lib:format("http://127.0.0.1:~b", [Port])).

%% @doc The highest number of requests that were being served at the same moment.
peak(Pid) ->
    ask(Pid, peak).

%% @doc How many times one path was requested.
hits(Pid, Path) ->
    maps:get(Path, ask(Pid, hits), 0).

boot(Parent, Options) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                      {packet, http_bin}, {backlog, 128}]),
    {ok, Port} = inet:port(Listen),
    Self = self(),
    spawn_link(fun() -> accept_loop(Listen, Self, Options#{port => Port}) end),
    Parent ! {?MODULE, self(), ready},
    loop(#{port => Port, in_flight => 0, peak => 0, hits => #{}}).

loop(#{in_flight := InFlight, peak := Peak, hits := Hits} = State) ->
    receive
        {started, Path} ->
            loop(State#{in_flight := InFlight + 1, peak := max(Peak, InFlight + 1),
                        hits := maps:update_with(Path, fun(N) -> N + 1 end, 1, Hits)});
        finished ->
            loop(State#{in_flight := InFlight - 1});
        {port, From, Ref} ->
            From ! {Ref, maps:get(port, State)},
            loop(State);
        {peak, From, Ref} ->
            From ! {Ref, Peak},
            loop(State);
        {hits, From, Ref} ->
            From ! {Ref, Hits},
            loop(State);
        {stop, From, Ref} ->
            From ! {Ref, ok}
    end.

accept_loop(Listen, Counter, Options) ->
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            spawn(fun() -> serve(Socket, Counter, Options) end),
            accept_loop(Listen, Counter, Options);
        {error, closed} ->
            ok
    end.

serve(Socket, Counter, Options) ->
    case read_request(Socket) of
        {ok, Path} ->
            Counter ! {started, Path},
            timer:sleep(maps:get(delay_ms, Options, 0)),
            respond(Socket, Path, Options),
            Counter ! finished,
            gen_tcp:close(Socket);
        error ->
            gen_tcp:close(Socket)
    end.

read_request(Socket) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, {http_request, _Method, {abs_path, Path}, _Version}} ->
            drain(Socket),
            {ok, hd(binary:split(Path, <<"?">>))};
        {ok, _Other} ->
            read_request(Socket);
        {error, _} ->
            error
    end.

drain(Socket) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, http_eoh} -> ok;
        {ok, _} -> drain(Socket);
        {error, _} -> ok
    end.

%% Announces gigabytes and then stalls. A client that followed the redirect would
%% sit here until its own timeout, which is exactly the failure this exists to
%% catch.
respond(Socket, <<"/huge">>, _Options) ->
    send(Socket, 200, [{<<"content-type">>, <<"application/octet-stream">>},
                       {<<"content-length">>, integer_to_binary(?HUGE_BYTES)}], <<>>),
    timer:sleep(30000);
respond(Socket, <<"/api/v1/database/download">>, Options) ->
    Location = iolist_to_binary(io_lib:format("http://127.0.0.1:~b/huge",
                                              [maps:get(port, Options)])),
    send(Socket, 302, [{<<"location">>, Location}], <<>>);
respond(Socket, Path, _Options) ->
    Ip = binary:part(Path, 1, byte_size(Path) - 1),
    Body = iolist_to_binary(json:encode(#{<<"ip">> => Ip, <<"is_vpn">> => false})),
    send(Socket, 200, [{<<"content-type">>, <<"application/json">>}], Body).

send(Socket, Status, Headers, Body) ->
    Length = case lists:keyfind(<<"content-length">>, 1, Headers) of
        {_, Declared} -> Declared;
        false -> integer_to_binary(byte_size(Body))
    end,
    All = lists:keystore(<<"content-length">>, 1, Headers, {<<"content-length">>, Length}),
    Lines = [io_lib:format("~s: ~s\r\n", [K, V]) || {K, V} <- All],
    Head = io_lib:format("HTTP/1.1 ~b ~s\r\nconnection: close\r\n", [Status, phrase(Status)]),
    inet:setopts(Socket, [{packet, raw}]),
    gen_tcp:send(Socket, [Head, Lines, "\r\n", Body]).

phrase(200) -> "OK";
phrase(302) -> "Found";
phrase(_) -> "Status".

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(origin_unresponsive)
    end.
