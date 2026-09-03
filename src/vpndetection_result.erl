%% @doc The wire body as an Erlang map, with absent and false kept apart.
%%
%% A key that is ABSENT from a result is one your plan does not include. It never
%% means "we could not check", so an absent key and `false' are genuinely
%% different answers, and `maps:get(is_hosting, Result, undefined)' is how you
%% tell them apart. `maps:get(is_hosting, Result, false)' is the reader for
%% callers who only care whether the address is flagged.
%%
%% A detail map that is present but empty (`#{}') means the flag above it is
%% false. A populated one always carries every one of its keys.
-module(vpndetection_result).

-export([from_wire/1, bogon/1]).

-export_type([result/0, detail/0]).

%% `is_vpn', `is_bogon' and `raw' are the only keys always present. A tag here
%% would be attached to the next FUNCTION by edoc and collide with its own,
%% which breaks doc chunk generation outright, so the prose lives on the module.
-type result() :: #{
    ip := binary(),
    is_vpn := boolean(),
    is_bogon := boolean(),
    raw := map(),
    is_hosting => boolean(),
    is_relay => boolean(),
    is_tor => boolean(),
    is_cdn => boolean(),
    is_resproxy => boolean(),
    is_dcproxy => boolean(),
    is_mobproxy => boolean(),
    vpn => detail(),
    hosting => detail(),
    relay => detail(),
    tor => detail(),
    cdn => detail(),
    resproxy => detail(),
    dcproxy => detail(),
    mobproxy => detail()
}.

-type detail() :: #{
    provider => binary(),
    confidence => binary(),
    method => binary(),
    first_seen => binary(),
    last_seen => binary(),
    hits => integer(),
    hits_days_pct => integer(),
    providers_num => integer()
}.

%% @doc Translate a decoded response body into a result.
%%
%% Folding over what the body HAS is what preserves absent-versus-false: a key
%% the server did not send cannot appear in the fold, so no plan-gated member
%% can be invented as `false'.
-spec from_wire(map()) -> result().
from_wire(Body) when is_map(Body) ->
    Mapped = maps:fold(fun(K, V, Acc) -> Acc#{key(K) => value(V)} end, #{}, Body),
    Mapped#{is_bogon => false, raw => Body}.

%% @doc The answer a bogon gets, in the full shape the API serves at its widest plan.
%%
%% This is deliberately the WIDEST shape whatever your plan is, so a caller must
%% not infer which fields they are entitled to from a bogon answer.
-spec bogon(binary()) -> result().
bogon(Ip) ->
    #{
        ip => Ip,
        is_bogon => true,
        is_vpn => false,
        is_hosting => false,
        is_relay => false,
        is_tor => false,
        is_cdn => false,
        is_resproxy => false,
        is_dcproxy => false,
        is_mobproxy => false,
        vpn => #{},
        hosting => #{},
        relay => #{},
        tor => #{},
        cdn => #{},
        resproxy => #{},
        dcproxy => #{},
        mobproxy => #{},
        raw => #{}
    }.

%% Every nested object in a lookup response is one of the detail shapes, so its
%% keys go through the same allowlist as the top level.
value(V) when is_map(V) ->
    maps:fold(fun(K, DV, Acc) -> Acc#{key(K) => DV} end, #{}, V);
value(V) ->
    V.

%% Only these names become atoms, and the set is fixed by the spec. Decoding a
%% server-supplied key straight to an atom is an atom table leak: the table is
%% never collected and is capped, so a response carrying arbitrary keys (which
%% the dataset metadata's `schema' and `sample' both do) would eventually take
%% the VM down. Anything unrecognized keeps its binary key.
key(<<"ip">>) -> ip;
key(<<"is_vpn">>) -> is_vpn;
key(<<"is_hosting">>) -> is_hosting;
key(<<"is_relay">>) -> is_relay;
key(<<"is_tor">>) -> is_tor;
key(<<"is_cdn">>) -> is_cdn;
key(<<"is_resproxy">>) -> is_resproxy;
key(<<"is_dcproxy">>) -> is_dcproxy;
key(<<"is_mobproxy">>) -> is_mobproxy;
key(<<"vpn">>) -> vpn;
key(<<"hosting">>) -> hosting;
key(<<"relay">>) -> relay;
key(<<"tor">>) -> tor;
key(<<"cdn">>) -> cdn;
key(<<"resproxy">>) -> resproxy;
key(<<"dcproxy">>) -> dcproxy;
key(<<"mobproxy">>) -> mobproxy;
key(<<"provider">>) -> provider;
key(<<"confidence">>) -> confidence;
key(<<"method">>) -> method;
key(<<"first_seen">>) -> first_seen;
key(<<"last_seen">>) -> last_seen;
key(<<"hits">>) -> hits;
key(<<"hits_days_pct">>) -> hits_days_pct;
key(<<"providers_num">>) -> providers_num;
key(Other) -> Other.
