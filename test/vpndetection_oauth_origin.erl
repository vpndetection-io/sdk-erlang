%% An authorization server on a real socket, for the OAuth suite. It answers a
%% script of responses in order and records every request as it ARRIVED: method,
%% path, query, lowercased headers and body, so a test asserts what left the
%% client rather than what the client meant to send.
%%
%% Past the script it answers 503. Past ?CAP requests it answers nothing at all,
%% so a loop in the client parks in a request instead of spinning, and the test
%% that started it ends it from outside.
-module(vpndetection_oauth_origin).

-export([start/1, stop/1, base_url/1, requests/1]).

-define(CAP, 40).

start(Script) ->
    Parent = self(),
    Pid = spawn_link(fun() -> boot(Parent, Script) end),
    receive
        {?MODULE, Pid, ready} -> Pid
    after 5000 ->
        error(origin_did_not_start)
    end.

stop(Pid) ->
    ask(Pid, stop).

base_url(Pid) ->
    iolist_to_binary(io_lib:format("http://127.0.0.1:~b", [ask(Pid, port)])).

%% @doc Every request so far, oldest first.
requests(Pid) ->
    ask(Pid, requests).

boot(Parent, Script) ->
    {ok, Listen} = gen_tcp:listen(0, [binary, {active, false}, {reuseaddr, true},
                                      {packet, http_bin}, {backlog, 128}]),
    {ok, Port} = inet:port(Listen),
    Self = self(),
    spawn_link(fun() -> accept_loop(Listen, Self) end),
    Parent ! {?MODULE, self(), ready},
    loop(#{port => Port, listen => Listen, script => Script, seen => []}).

loop(#{script := Script, seen := Seen} = State) ->
    receive
        {request, From, Request} ->
            {Response, Rest} = case {length(Seen) >= ?CAP, Script} of
                {true, _} -> {hold, Script};
                {false, [Next | Tail]} -> {Next, Tail};
                {false, []} -> {#{<<"status">> => 503, <<"rawBody">> => <<>>}, []}
            end,
            From ! {response, Response},
            loop(State#{script := Rest, seen := [Request | Seen]});
        {requests, From, Ref} ->
            From ! {Ref, lists:reverse(Seen)},
            loop(State);
        {port, From, Ref} ->
            From ! {Ref, maps:get(port, State)},
            loop(State);
        {stop, From, Ref} ->
            gen_tcp:close(maps:get(listen, State)),
            From ! {Ref, ok}
    end.

accept_loop(Listen, Owner) ->
    case gen_tcp:accept(Listen) of
        {ok, Socket} ->
            spawn(fun() -> serve(Socket, Owner) end),
            accept_loop(Listen, Owner);
        {error, _} ->
            ok
    end.

serve(Socket, Owner) ->
    case read_request(Socket) of
        {ok, Request} ->
            Owner ! {request, self(), Request},
            receive
                {response, hold} -> receive after 60000 -> ok end;
                {response, Response} -> respond(Socket, Response)
            end;
        error ->
            ok
    end,
    gen_tcp:close(Socket).

read_request(Socket) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, {http_request, Method, {abs_path, Target}, _Version}} ->
            [Path | Query] = binary:split(Target, <<"?">>),
            Headers = headers(Socket, []),
            Length = binary_to_integer(proplists:get_value(<<"content-length">>, Headers, <<"0">>)),
            {ok, #{method => text(Method), path => Path, query => iolist_to_binary(Query),
                   headers => Headers, body => body(Socket, Length)}};
        _ ->
            error
    end.

headers(Socket, Acc) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, {http_header, _, Name, _, Value}} -> headers(Socket, [{lower(Name), Value} | Acc]);
        _ -> lists:reverse(Acc)
    end.

body(_Socket, 0) ->
    <<>>;
body(Socket, Length) ->
    ok = inet:setopts(Socket, [{packet, raw}]),
    {ok, Body} = gen_tcp:recv(Socket, Length, 5000),
    Body.

respond(Socket, #{<<"status">> := Status} = Response) ->
    Body = case Response of
        #{<<"rawBody">> := Raw} -> Raw;
        #{<<"body">> := Json} -> iolist_to_binary(json:encode(Json))
    end,
    Head = io_lib:format("HTTP/1.1 ~b X\r\ncontent-type: application/json\r\ncontent-length: ~b\r\n"
                         "connection: close\r\n\r\n", [Status, byte_size(Body)]),
    ok = inet:setopts(Socket, [{packet, raw}]),
    gen_tcp:send(Socket, [Head, Body]).

%% http_bin hands a well-known header name over as an atom and any other as a
%% binary, in the case it arrived in.
lower(Name) ->
    string:lowercase(text(Name)).

text(Name) when is_atom(Name) -> atom_to_binary(Name);
text(Name) -> Name.

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(origin_unresponsive)
    end.
