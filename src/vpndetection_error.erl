%% @doc Why a request failed, and whether trying it again could ever help.
-module(vpndetection_error).

-export([from_response/3, from_transport/1]).

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
    retry_after => non_neg_integer()
}.

%% @doc Classify a non-2xx response.
-spec from_response(100..599, [{binary(), binary()}], binary()) -> error().
from_response(Status, Headers, Body) ->
    Message = message_of(Body, Status),
    classify(Status, retry_after(Headers), Message).

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
%% a caller never has to know which one they hit.
message_of(Body, Status) ->
    Decoded = try json:decode(Body) catch _:_ -> #{} end,
    case Decoded of
        #{<<"error">> := M} when is_binary(M) -> M;
        #{<<"rc">> := M} when is_binary(M) -> M;
        _ -> iolist_to_binary(io_lib:format("request failed with status ~b", [Status]))
    end.

retry_after(Headers) ->
    case lists:keyfind(<<"retry-after">>, 1, Headers) of
        {_, Value} -> seconds(string:trim(Value));
        false -> undefined
    end.

seconds(<<>>) ->
    undefined;
seconds(Value) ->
    try binary_to_integer(Value) of
        Seconds when Seconds >= 0 -> Seconds;
        _ -> undefined
    catch
        _:_ -> from_http_date(Value)
    end.

%% The header also permits an HTTP date, in which case the wait is the distance
%% from now rather than the value itself.
from_http_date(Value) ->
    try httpd_util:convert_request_date(binary_to_list(Value)) of
        bad_date ->
            undefined;
        DateTime ->
            Now = calendar:universal_time(),
            Delta = calendar:datetime_to_gregorian_seconds(DateTime)
                - calendar:datetime_to_gregorian_seconds(Now),
            max(0, Delta)
    catch
        _:_ -> undefined
    end.
