%% @doc How the client address is decided.
%%
%% There is no portable default: a framework's own accessor may return the
%% socket peer, or may already have walked a proxy chain, depending on the
%% framework and on how the application configured it. You know your framework
%% and your edge, so this is yours to choose - and anything of this shape works,
%% so an edge we have never heard of is a fun rather than a feature request:
%%
%% ```
%% fun(View) -> (maps:get(header, View))(<<"x-real-ip">>) end
%% '''
-module(vpndetection_selectors).

-export([framework_ip/0, xff/1, header/1, proxy_protocol/1, resolve/2]).

-export_type([view/0, selector/0]).

%% Enough of an incoming request for a selector to work with, whatever framework
%% it came from. An adapter supplies one of these per request.
-type view() :: #{
    %% A request header by name (lowercase), or `undefined' when absent.
    header := fun((binary()) -> binary() | undefined),
    %% The framework's own client-address accessor.
    framework_ip := fun(() -> binary() | undefined),
    %% The source address a PROXY protocol header carried, where the adapter
    %% can read one (Cowboy's `proxy_header'), or `undefined' when none came.
    proxy_address => fun(() -> binary() | undefined)
}.

-type selector() :: fun((view()) -> binary() | undefined).

%% @doc The framework's own client-address accessor. The default.
-spec framework_ip() -> selector().
framework_ip() ->
    fun(View) -> (maps:get(framework_ip, View))() end.

%% @doc An address from `X-Forwarded-For'.
%%
%% The LEFT-MOST entry (`Depth' 0) is whatever the caller sent, because proxies
%% append to this header, so a visitor who sets it themselves appears first and
%% this returns their forgery. It is only trustworthy when an edge you control
%% overwrites the header. When you know how many proxies sit in front, count
%% from the right: depth 1 is the address your nearest proxy saw.
-spec xff(non_neg_integer()) -> selector().
xff(Depth) ->
    fun(View) ->
        Raw =
            case (maps:get(header, View))(<<"x-forwarded-for">>) of
                undefined -> <<>>;
                Value -> Value
            end,
        Chain = [
            E
         || E <- [string:trim(P) || P <- binary:split(Raw, <<",">>, [global])], E =/= <<>>
        ],
        case Chain of
            [] -> (maps:get(framework_ip, View))();
            _ -> lists:nth(index(Depth, length(Chain)), Chain)
        end
    end.

%% @doc An address from a single-value header your edge writes -
%% `header(<<"cf-connecting-ip">>)' behind Cloudflare. Falls back to the
%% framework's accessor when the header is absent.
-spec header(binary() | string()) -> selector().
header(Name) ->
    Lower = string:lowercase(iolist_to_binary(Name)),
    fun(View) ->
        case (maps:get(header, View))(Lower) of
            undefined ->
                (maps:get(framework_ip, View))();
            Value ->
                case string:trim(Value) of
                    <<>> -> (maps:get(framework_ip, View))();
                    Trimmed -> Trimmed
                end
        end
    end.

%% @doc The source address of a PROXY protocol header (v1 or v2), read only on a
%% connection from `Trusted', a list of addresses or CIDR blocks your balancers
%% send from. For a listener started with `proxy_header => true' behind a
%% balancer that speaks the protocol, such as nginx's stream module with
%% `proxy_protocol on' or HAProxy's `send-proxy'.
%%
%% The header is whatever the connecting peer wrote, so on a connection from
%% anywhere else, or one whose header names no source (a balancer's own health
%% check), this answers the socket peer. Raises `{badarg, {trusted, Spec}}' for
%% an entry that is not an address or a CIDR block.
-spec proxy_protocol([binary() | string()]) -> selector().
proxy_protocol(Trusted) when is_list(Trusted) ->
    Ranges = [trusted_range(Spec) || Spec <- Trusted],
    fun(View) ->
        Peer = (maps:get(framework_ip, View))(),
        case in_ranges(Peer, Ranges) of
            true -> proxied(View, Peer);
            false -> Peer
        end
    end.

proxied(View, Peer) ->
    case maps:get(proxy_address, View, undefined) of
        undefined ->
            Peer;
        Read ->
            case Read() of
                undefined -> Peer;
                Address -> Address
            end
    end.

trusted_range(Spec) ->
    Bin = iolist_to_binary(Spec),
    {Address, Bits} =
        case binary:split(Bin, <<"/">>) of
            [A] -> {A, undefined};
            [A, B] -> {A, prefix_bits(B)}
        end,
    case inet:parse_strict_address(binary_to_list(Address)) of
        {ok, Parsed} ->
            Width = width(Parsed),
            Prefix =
                case Bits of
                    undefined -> Width;
                    N when is_integer(N), N >= 0, N =< Width -> N;
                    _ -> error({badarg, {trusted, Spec}})
                end,
            {Width, Prefix, to_int(Parsed) bsr (Width - Prefix)};
        {error, _} ->
            error({badarg, {trusted, Spec}})
    end.

prefix_bits(Bits) ->
    try
        binary_to_integer(Bits)
    catch
        error:badarg -> invalid
    end.

in_ranges(undefined, _Ranges) ->
    false;
in_ranges(Peer, Ranges) ->
    case inet:parse_strict_address(binary_to_list(vpndetection_bogon:unmapped(Peer))) of
        {ok, Parsed} ->
            Width = width(Parsed),
            Int = to_int(Parsed),
            lists:any(
                fun({W, Prefix, Net}) -> W =:= Width andalso Int bsr (Width - Prefix) =:= Net end,
                Ranges
            );
        {error, _} ->
            false
    end.

width(Address) when tuple_size(Address) =:= 4 -> 32;
width(Address) when tuple_size(Address) =:= 8 -> 128.

to_int(Address) ->
    Step = width(Address) div tuple_size(Address),
    lists:foldl(fun(Part, Acc) -> (Acc bsl Step) bor Part end, 0, tuple_to_list(Address)).

%% @doc Run a selector over one request view.
-spec resolve(selector(), view()) -> binary() | undefined.
resolve(Selector, View) ->
    Selector(View).

%% Past the chain's length the depth is meaningless, so this falls back to the
%% left-most rather than indexing off the end.
index(Depth, Length) when Depth =:= 0; Depth > Length -> 1;
index(Depth, Length) -> Length - Depth + 1.
