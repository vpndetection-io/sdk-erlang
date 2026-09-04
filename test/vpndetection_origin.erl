%% A real HTTP origin on a real socket, for the claims a stubbed transport cannot
%% make honestly: that httpc itself lets the configured number of requests run at
%% once, that a redirect to a huge file is not followed, and that a dataset
%% transfer really does move bytes over a socket and stops when they run out.
%%
%% It doubles as the object storage behind a 302, so a download test can check
%% that the second request carried no credential.
-module(vpndetection_origin).

-export([start/1, stop/1, base_url/1, peak/1, hits/2, authorized/2, payload/0]).

-define(HUGE_BYTES, 5000000000).
-define(PAYLOAD_BYTES, 3000000).
-define(WRITE_BYTES, 65536).

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

%% @doc Whether ANY request for one path arrived with an authorization header.
%% `false' for a path nobody asked for, which is why callers check the hit count
%% first: an unasked path trivially carried no credential.
authorized(Pid, Path) ->
    maps:get(Path, ask(Pid, authorized), false).

%% @doc The bytes `/dataset' serves. Deterministic, so a test can hash them.
payload() ->
    Seed = <<"vpndetection dataset payload, 64 bytes of it, repeated to size.\n">>,
    Repeats = ?PAYLOAD_BYTES div byte_size(Seed),
    binary:part(binary:copy(Seed, Repeats + 1), 0, ?PAYLOAD_BYTES).

boot(Parent, Options) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                      {packet, http_bin}, {backlog, 128}]),
    {ok, Port} = inet:port(Listen),
    Self = self(),
    spawn_link(fun() -> accept_loop(Listen, Self, Options#{port => Port}) end),
    Parent ! {?MODULE, self(), ready},
    loop(#{port => Port, in_flight => 0, peak => 0, hits => #{}, authorized => #{}}).

loop(#{in_flight := InFlight, peak := Peak, hits := Hits, authorized := Auth} = State) ->
    receive
        {started, Path, Credentialed} ->
            loop(State#{in_flight := InFlight + 1, peak := max(Peak, InFlight + 1),
                        hits := maps:update_with(Path, fun(N) -> N + 1 end, 1, Hits),
                        authorized := maps:update_with(Path, fun(A) -> A orelse Credentialed end,
                                                       Credentialed, Auth)});
        finished ->
            loop(State#{in_flight := InFlight - 1});
        {Key, From, Ref} when Key =:= port; Key =:= peak; Key =:= hits; Key =:= authorized ->
            From ! {Ref, maps:get(Key, State)},
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
        {ok, Path, Query, Credentialed} ->
            Counter ! {started, Path, Credentialed},
            timer:sleep(maps:get(delay_ms, Options, 0)),
            respond(Socket, Path, Query, Options),
            Counter ! finished,
            gen_tcp:close(Socket);
        error ->
            gen_tcp:close(Socket)
    end.

read_request(Socket) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, {http_request, _Method, {abs_path, Target}, _Version}} ->
            [Path | Rest] = binary:split(Target, <<"?">>),
            {ok, Path, iolist_to_binary(Rest), headers(Socket, false)};
        {ok, _Other} ->
            read_request(Socket);
        {error, _} ->
            error
    end.

%% Answers whether a credential was presented, which is the whole question at the
%% object storage end of a download.
headers(Socket, Credentialed) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, http_eoh} -> Credentialed;
        {ok, {http_header, _, 'Authorization', _, _}} -> headers(Socket, true);
        {ok, _} -> headers(Socket, Credentialed);
        {error, _} -> Credentialed
    end.

%% Announces gigabytes and then stalls. A client that followed the redirect would
%% sit here until its own timeout, which is exactly the failure this exists to
%% catch.
respond(Socket, <<"/huge">>, _Query, _Options) ->
    send(Socket, 200, [{<<"content-type">>, <<"application/octet-stream">>},
                       {<<"content-length">>, integer_to_binary(?HUGE_BYTES)}], <<>>),
    timer:sleep(30000);
%% Written out in pieces with a pause between them, so the body cannot arrive in
%% one socket read however generous the receive buffer is. That is what makes
%% "the client saw more than one chunk" a claim about the client rather than
%% about the kernel it happened to run on.
respond(Socket, <<"/dataset">>, _Query, _Options) ->
    Whole = payload(),
    send(Socket, 200, [{<<"content-type">>, <<"application/gzip">>},
                       {<<"content-length">>, integer_to_binary(byte_size(Whole))}], <<>>),
    trickle(Socket, Whole);
%% Declares the whole payload and hands over a tenth of it. A client that reads
%% until the socket closes calls this a complete transfer of a short file.
respond(Socket, <<"/truncated">>, _Query, _Options) ->
    Whole = payload(),
    send(Socket, 200, [{<<"content-type">>, <<"application/gzip">>},
                       {<<"content-length">>, integer_to_binary(byte_size(Whole))}],
         binary:part(Whole, 0, byte_size(Whole) div 10));
respond(Socket, <<"/expired">>, _Query, _Options) ->
    send(Socket, 403, [{<<"content-type">>, <<"application/xml">>}],
         <<"<Error><Code>AccessDenied</Code></Error>">>);
respond(Socket, <<"/api/v1/database/download">>, Query, Options) ->
    case dataset(Query) of
        <<"unlicensed">> ->
            send(Socket, 403, [{<<"content-type">>, <<"application/json">>}],
                 iolist_to_binary(json:encode(#{<<"rc">> => <<"NOT_LICENSED">>})));
        Id ->
            Location = iolist_to_binary(io_lib:format("http://127.0.0.1:~b/~s",
                                                      [maps:get(port, Options), Id])),
            send(Socket, 302, [{<<"location">>, Location}], <<>>)
    end;
respond(Socket, Path, _Query, _Options) ->
    Ip = binary:part(Path, 1, byte_size(Path) - 1),
    Body = iolist_to_binary(json:encode(#{<<"ip">> => Ip, <<"is_vpn">> => false})),
    send(Socket, 200, [{<<"content-type">>, <<"application/json">>}], Body).

%% The `id' the client asked for doubles as the name of the file the redirect
%% points at, so one origin serves every download case.
dataset(Query) ->
    case [V || {<<"id">>, V} <- uri_string:dissect_query(Query)] of
        [Id | _] -> Id;
        [] -> <<"huge">>
    end.

trickle(_Socket, <<>>) ->
    ok;
trickle(Socket, Body) ->
    Take = min(?WRITE_BYTES, byte_size(Body)),
    <<Piece:Take/binary, Rest/binary>> = Body,
    case gen_tcp:send(Socket, Piece) of
        ok -> timer:sleep(1), trickle(Socket, Rest);
        {error, _} -> ok
    end.

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
phrase(403) -> "Forbidden";
phrase(_) -> "Status".

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(origin_unresponsive)
    end.
