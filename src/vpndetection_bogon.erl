%% @doc Local classification of addresses that can never be VPN or proxy infrastructure.
-module(vpndetection_bogon).

-export([is_bogon/1, unmapped/1]).

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
    %% An IPv4-mapped address is judged as the IPv4 address it carries.
    case inet:parse_address(Ip) of
        {ok, {0, 0, 0, 0, 0, 16#ffff, Hi, Lo}} -> in_any(to_int(v4_of(Hi, Lo), 8), V4);
        {ok, Addr} when tuple_size(Addr) =:= 4 -> in_any(to_int(Addr, 8), V4);
        {ok, Addr} when tuple_size(Addr) =:= 8 -> in_any(to_int(Addr, 16), V6);
        {error, _} -> false
    end;
is_bogon(_) ->
    false.

%% @doc The IPv4 address an IPv4-mapped IPv6 address (`::ffff:a.b.c.d', in any
%% spelling) carries, dotted, and any other address as given.
%%
%% A server listening on `::' sees every IPv4 visitor in that form, which read
%% whole is inside `::ffff:0:0/96', so judging it whole would answer every such
%% visitor locally as a bogon. `::a.b.c.d' is IPv4-compatible rather than
%% mapped, and stays IPv6.
-spec unmapped(binary()) -> binary().
unmapped(Ip) when is_binary(Ip) ->
    case binary:match(Ip, <<":">>) =/= nomatch andalso inet:parse_address(binary_to_list(Ip)) of
        {ok, {0, 0, 0, 0, 0, 16#ffff, Hi, Lo}} -> list_to_binary(inet:ntoa(v4_of(Hi, Lo)));
        _ -> Ip
    end.

v4_of(Hi, Lo) ->
    {Hi bsr 8, Hi band 16#ff, Lo bsr 8, Lo band 16#ff}.

%% The parsed table is derived from a compile-time constant and never changes,
%% so it is computed once and read without copying thereafter. Parsing it on
%% every call would re-walk 80 CIDRs to answer a question with a fixed answer.
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
