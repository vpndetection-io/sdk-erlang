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

-export([framework_ip/0, xff/1, header/1, resolve/2]).

-export_type([view/0, selector/0]).

%% Enough of an incoming request for a selector to work with, whatever framework
%% it came from. An adapter supplies one of these per request.
-type view() :: #{
    %% A request header by name (lowercase), or `undefined' when absent.
    header := fun((binary()) -> binary() | undefined),
    %% The framework's own client-address accessor.
    framework_ip := fun(() -> binary() | undefined)
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

%% @doc Run a selector over one request view.
-spec resolve(selector(), view()) -> binary() | undefined.
resolve(Selector, View) ->
    Selector(View).

%% Past the chain's length the depth is meaningless, so this falls back to the
%% left-most rather than indexing off the end.
index(Depth, Length) when Depth =:= 0; Depth > Length -> 1;
index(Depth, Length) -> Length - Depth + 1.
