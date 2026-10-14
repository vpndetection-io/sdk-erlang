%% @doc Why a request failed, and whether trying it again could ever help.
-module(vpndetection_error).

-export([from_response/3, from_entry/2, from_transport/1, from_oauth/4, local_expiry/0]).

-export_type([kind/0, error/0]).

%% `rate_limited' and `quota_exceeded' both arrive as HTTP 429 and are NOT the
%% same thing. A rate limit is the API protecting itself and carries
%% `Retry-After'; retrying works. A spent quota carries no such header and
%% retrying will not help until the window rolls over or the limit is raised.
%% The header is the only thing that distinguishes them.
%% `io' is the one kind the API never causes: it is a local filesystem failure
%% while a download is being written, which is the caller's disk rather than our
%% service, and so is never worth retrying against the API.
-type kind() :: bad_request
              | unauthorized
              | forbidden
              | rate_limited
              | quota_exceeded
              | server_error
              | network
              | io.

-type error() :: #{
    kind := kind(),
    message := binary(),
    retryable := boolean(),
    status => 100..599,
    retry_after => non_neg_integer(),
    error_code => binary(),
    error_description => binary()
}.

-define(DAYS, [<<"Mon">>, <<"Tue">>, <<"Wed">>, <<"Thu">>, <<"Fri">>, <<"Sat">>, <<"Sun">>]).
-define(WEEKDAYS, [<<"Monday">>, <<"Tuesday">>, <<"Wednesday">>, <<"Thursday">>, <<"Friday">>,
                   <<"Saturday">>, <<"Sunday">>]).
-define(MONTHS, [<<"Jan">>, <<"Feb">>, <<"Mar">>, <<"Apr">>, <<"May">>, <<"Jun">>, <<"Jul">>,
                 <<"Aug">>, <<"Sep">>, <<"Oct">>, <<"Nov">>, <<"Dec">>]).

%% @doc Classify a non-2xx response.
-spec from_response(100..599, [{binary(), binary()}], binary()) -> error().
from_response(Status, Headers, Body) ->
    Message = message_of(Body, Status),
    classify(Status, retry_after(Headers), Message).

%% @doc A per-entry failure inside a successful batch: the status the single
%% lookup would have answered, and its message, with no headers at all - so a
%% 429 here is a spent allowance, which is the only kind the API puts in an
%% entry.
-spec from_entry(100..599, binary()) -> error().
from_entry(Status, Message) when is_integer(Status), is_binary(Message) ->
    classify(Status, undefined, Message).

%% @doc The authorization server refusing an OAuth request: the ordinary error for
%% its status, plus the RFC 6749 `error' code, and never retryable, because every
%% code answers the request as it was made.
-spec from_oauth(400..499, [{binary(), binary()}], binary(), binary() | undefined) -> error().
from_oauth(Status, Headers, Code, Description) ->
    Base = maps:remove(retry_after, classify(Status, retry_after(Headers), Code)),
    case Description of
        undefined ->
            Base#{retryable := false, error_code => Code};
        _ ->
            Base#{retryable := false, error_code => Code, error_description => Description,
                  message := <<Code/binary, ": ", Description/binary>>}
    end.

%% @doc A device-code poll reaching the code's lifetime before the server said so:
%% coded `expired_token', and without a status, which is how it is told apart.
-spec local_expiry() -> error().
local_expiry() ->
    #{kind => bad_request, retryable => false, message => <<"expired_token">>,
      error_code => <<"expired_token">>}.

%% @doc Classify a failure that never produced a response at all.
-spec from_transport(term()) -> error().
%% The sink refused the bytes, so nothing about the API is wrong and a second
%% attempt would fail the same way. The message is built where the destination is
%% known rather than reconstructed here.
from_transport({sink_failed, Message}) when is_binary(Message) ->
    #{kind => io, message => Message, retryable => false};
%% A transfer that broke after bytes had already reached the sink. NOT retryable
%% however transient the cause: those bytes are written, and repeating the
%% request would append a second copy of the body to them.
from_transport({transfer_failed, Written, Reason}) ->
    #{kind => network, retryable => false,
      message => iolist_to_binary(io_lib:format("the transfer failed after ~b bytes: ~p",
                                                [Written, Reason]))};
from_transport(Reason) ->
    #{kind => network, message => iolist_to_binary(io_lib:format("~p", [Reason])), retryable => true}.

classify(429, undefined, Message) ->
    %% No Retry-After means an allowance is spent. Nothing else in the response
    %% separates that from a transient rate limit.
    #{kind => quota_exceeded, message => Message, retryable => false, status => 429};
classify(429, Seconds, Message) ->
    #{kind => rate_limited, message => Message, retryable => true, status => 429,
      retry_after => Seconds};
classify(400, _, Message) ->
    #{kind => bad_request, message => Message, retryable => false, status => 400};
classify(401, _, Message) ->
    #{kind => unauthorized, message => Message, retryable => false, status => 401};
classify(403, _, Message) ->
    #{kind => forbidden, message => Message, retryable => false, status => 403};
classify(Status, _, Message) when Status < 500 ->
    %% Any other 4xx is a CLIENT error. Falling through to the server_error
    %% default below would make it retryable, so a bad dataset id would be
    %% retried twice before failing. Classify on the RANGE, not on a list.
    #{kind => bad_request, message => Message, retryable => false, status => Status};
classify(Status, _, Message) ->
    #{kind => server_error, message => Message, retryable => true, status => Status}.

%% The two APIs behind this host answer with different envelopes: the lookup
%% endpoint uses `error', the database endpoints use `rc'. Both are read here so
%% a caller never has to know which one they hit, and the first that says
%% something is the message: an empty one says nothing, so
%% `{"error": "", "rc": "QUOTA_EXCEEDED"}' reads as QUOTA_EXCEEDED.
message_of(Body, Status) ->
    Decoded = try json:decode(Body) catch _:_ -> #{} end,
    Said = [Value || is_map(Decoded), Key <- [<<"error">>, <<"rc">>],
                     Value <- [maps:get(Key, Decoded, undefined)], is_binary(Value), Value =/= <<>>],
    case Said of
        [Message | _] -> Message;
        [] -> iolist_to_binary(io_lib:format("request failed with status ~b", [Status]))
    end.

retry_after(Headers) ->
    case lists:keyfind(<<"retry-after">>, 1, Headers) of
        {_, Value} -> seconds(ows(Value));
        false -> undefined
    end.

%% Digits, or an HTTP date, and nothing else, so a value that is neither is no
%% Retry-After at all and the 429 a spent quota. `binary_to_integer/1' takes a
%% sign, and httpd_util's date reader takes any zone as GMT and an hour or a day
%% that does not exist, raising out of the call for some of them.
seconds(Value) ->
    case Value =/= <<>> andalso digits(Value) of
        true -> binary_to_integer(Value);
        false -> http_date(Value)
    end.

%% RFC 9110's three forms, in GMT: IMF-fixdate, RFC 850 and asctime. The wait is
%% the distance from now rather than the value itself.
http_date(<<Day:3/binary, ", ", D:2/binary, " ", Mon:3/binary, " ", Y:4/binary, " ", Time:8/binary,
            " GMT">>) ->
    named(lists:member(Day, ?DAYS), Y, Mon, D, Time);
http_date(<<Day:3/binary, " ", Mon:3/binary, " ", D:2/binary, " ", Time:8/binary, " ", Y:4/binary>>) ->
    named(lists:member(Day, ?DAYS), Y, Mon, padded(D), Time);
http_date(Value) ->
    case binary:split(Value, <<", ">>) of
        [Weekday, <<D:2/binary, "-", Mon:3/binary, "-", YY:2/binary, " ", Time:8/binary, " GMT">>] ->
            named(lists:member(Weekday, ?WEEKDAYS), century(YY), Mon, D, Time);
        _ ->
            undefined
    end.

named(false, _Y, _Mon, _D, _Time) ->
    undefined;
named(true, Y, Mon, D, <<H:2/binary, ":", Mi:2/binary, ":", S:2/binary>>) ->
    case digits(<<Y/binary, D/binary, H/binary, Mi/binary, S/binary>>) of
        true -> until(Y, month(Mon, ?MONTHS, 1), D, H, Mi, S);
        false -> undefined
    end;
named(true, _Y, _Mon, _D, _Time) ->
    undefined.

until(_Y, undefined, _D, _H, _Mi, _S) ->
    undefined;
until(Y, Month, D, H, Mi, S) ->
    Date = {binary_to_integer(Y), Month, binary_to_integer(D)},
    Time = {binary_to_integer(H), binary_to_integer(Mi), binary_to_integer(S)},
    case calendar:valid_date(Date) andalso element(1, Time) < 24 andalso element(2, Time) < 60
         andalso element(3, Time) < 60 of
        true ->
            Delta = calendar:datetime_to_gregorian_seconds({Date, Time})
                - calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
            max(0, Delta);
        false ->
            undefined
    end.

%% A two-digit year more than 50 years ahead is the most recent past one with
%% those digits, as RFC 9110 has a recipient read it.
century(<<YY:2/binary>> = Digits) ->
    case digits(Digits) of
        true ->
            {{Now, _, _}, _} = calendar:universal_time(),
            Year = Now - Now rem 100 + binary_to_integer(YY),
            Read = case Year > Now + 50 of
                true -> Year - 100;
                false -> Year
            end,
            integer_to_binary(Read);
        false ->
            <<"x">>
    end.

%% The space and tabs either side of a field value are not part of it.
ows(<<C, Rest/binary>>) when C =:= $\s; C =:= $\t ->
    ows(Rest);
ows(Value) ->
    Size = byte_size(Value),
    case Size > 0 andalso binary:last(Value) of
        C when C =:= $\s; C =:= $\t -> ows(binary:part(Value, 0, Size - 1));
        _ -> Value
    end.

padded(<<" ", Digit>>) -> <<"0", Digit>>;
padded(D) -> D.

month(_Mon, [], _N) -> undefined;
month(Mon, [Mon | _], N) -> N;
month(Mon, [_ | Rest], N) -> month(Mon, Rest, N + 1).

digits(Value) ->
    lists:all(fun(C) -> C >= $0 andalso C =< $9 end, binary_to_list(Value)).
