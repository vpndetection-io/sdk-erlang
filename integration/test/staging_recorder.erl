%% Wraps the library's OWN transport so a test can say what reached the wire.
%%
%% Only derived facts leave here. A failing assertion prints its operands, so
%% holding on to the request itself is how a key ends up in a public CI log:
%% whether the key was carried is a boolean, and no caller ever sees the key.
-module(staging_recorder).

-export([start/1, stop/1, http/1, facts/1, carried_key/1, requests/1, paths/1, record/3]).

-export_type([fact/0]).

-type fact() :: #{origin := binary(), path := binary(), carried_key := boolean()}.

-spec start(binary() | undefined) -> pid().
start(Key) ->
    vpndetection_http:ensure_ready(),
    spawn_link(fun() -> loop(Key, []) end).

-spec stop(pid()) -> ok.
stop(Pid) ->
    ask(Pid, stop).

%% @doc A transport to hand to `vpndetection:new/1'. It delegates to the client's
%% real one, so what is measured is the library's own request rather than a
%% reimplementation of it.
-spec http(pid()) -> vpndetection_http:http_fun().
http(Pid) ->
    Send = vpndetection_http:httpc_fun(),
    fun(Request) -> ?MODULE:record(Pid, Request, Send) end.

-spec record(pid(), vpndetection_http:request(), vpndetection_http:http_fun()) ->
    vpndetection_http:response().
record(Pid, Request, Send) ->
    Pid ! {seen, Request},
    Send(Request).

-spec facts(pid()) -> [fact()].
facts(Pid) ->
    ask(Pid, facts).

%% @doc Whether the key was presented on ANY request this recorder saw.
-spec carried_key(pid()) -> boolean().
carried_key(Pid) ->
    lists:any(fun(#{carried_key := Carried}) -> Carried end, facts(Pid)).

-spec requests(pid()) -> non_neg_integer().
requests(Pid) ->
    length(facts(Pid)).

%% @doc The distinct paths asked for, sorted. Distinct rather than a call count,
%% so a retry against a wobbling staging cannot read as a failure to deduplicate.
-spec paths(pid()) -> [binary()].
paths(Pid) ->
    lists:usort([Path || #{path := Path} <- facts(Pid)]).

loop(Key, Facts) ->
    receive
        {seen, Request} ->
            loop(Key, [fact(Key, Request) | Facts]);
        {facts, From, Ref} ->
            From ! {Ref, lists:reverse(Facts)},
            loop(Key, Facts);
        {stop, From, Ref} ->
            From ! {Ref, ok}
    end.

fact(Key, #{url := Url} = Request) ->
    #{scheme := Scheme, host := Host, path := Path} = uri_string:parse(Url),
    #{origin => iolist_to_binary([Scheme, "://", Host]),
      path => Path,
      carried_key => carried(Key, Request)}.

%% The URL is checked as well as the headers: a key moved into a query parameter
%% is still a key handed to whoever is on the other end.
carried(undefined, _Request) ->
    false;
carried(Key, #{url := Url, headers := Headers}) ->
    lists:any(fun(Value) -> binary:match(Value, Key) =/= nomatch end,
              [Url | [V || {_K, V} <- Headers]]).

ask(Pid, Message) ->
    Ref = make_ref(),
    Pid ! {Message, self(), Ref},
    receive
        {Ref, Reply} -> Reply
    after 5000 ->
        error(recorder_unresponsive)
    end.
