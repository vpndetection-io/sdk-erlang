%% @doc Local classification of addresses that can never be VPN or proxy infrastructure.
-module(vpndetection_bogon).

-export([is_bogon/1]).

-define(RANGES, {?MODULE, ranges}).

%% @doc Whether an address is private, loopback, link-local, documentation,
%% multicast or otherwise not routable on the public internet, including the
%% IPv6 equivalents and the 6to4 and Teredo ranges that wrap them.
%%
%% Anything that is not a well-formed address is `false': the API decides what
%% counts as an address, and answering `true' here would swallow the 400 that
%% tells the caller their input was wrong.
-spec is_bogon(binary() | string()) -> boolean().
is_bogon(Ip) when is_binary(Ip) ->
    is_bogon(binary_to_list(Ip));
is_bogon(Ip) when is_list(Ip) ->
    {V4, V6} = ranges(),
    %% A v6 literal is matched against the v6 table only, so ::ffff:10.0.0.1 is
    %% resolved by the v6 ::ffff:0:0/96 entry rather than by unmapping it to
    %% 10.0.0.1 and consulting the v4 table. Every other SDK routes the same way.
    case inet:parse_address(Ip) of
        {ok, Addr} when tuple_size(Addr) =:= 4 -> in_any(to_int(Addr, 8), V4);
        {ok, Addr} when tuple_size(Addr) =:= 8 -> in_any(to_int(Addr, 16), V6);
        {error, _} -> false
    end;
is_bogon(_) ->
    false.

%% The parsed table is derived from a compile-time constant and never changes,
%% so it is computed once and read without copying thereafter. Parsing it on
%% every call would re-walk 54 CIDRs to answer a question with a fixed answer.
ranges() ->
    case persistent_term:get(?RANGES, undefined) of
        undefined ->
            Parsed = {parse(vpndetection_bogons:v4(), 32), parse(vpndetection_bogons:v6(), 128)},
            persistent_term:put(?RANGES, Parsed),
            Parsed;
        Parsed ->
            Parsed
    end.

parse(Cidrs, Width) ->
    [parse_one(C, Width) || C <- Cidrs].

parse_one(Cidr, Width) ->
    [Net, BitsBin] = binary:split(Cidr, <<"/">>),
    Bits = binary_to_integer(BitsBin),
    {ok, Addr} = inet:parse_address(binary_to_list(Net)),
    Step = Width div tuple_size(Addr),
    Mask = mask(Bits, Width),
    {to_int(Addr, Step) band Mask, Mask}.

mask(0, _Width) ->
    0;
mask(Bits, Width) ->
    ((1 bsl Bits) - 1) bsl (Width - Bits).

to_int(Addr, Step) ->
    lists:foldl(fun(Part, Acc) -> (Acc bsl Step) bor Part end, 0, tuple_to_list(Addr)).

in_any(Addr, Ranges) ->
    lists:any(fun({Net, Mask}) -> (Addr band Mask) =:= Net end, Ranges).
