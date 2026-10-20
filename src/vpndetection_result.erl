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

-export_type([result/0, detail/0, location/0, asn/0]).

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
    is_pubproxy => boolean(),
    vpn => detail(),
    hosting => detail(),
    relay => detail(),
    tor => detail(),
    cdn => detail(),
    resproxy => detail(),
    dcproxy => detail(),
    mobproxy => detail(),
    pubproxy => detail(),
    location => location(),
    asn => asn()
}.

%% `method' is deprecated: no plan is answered with it since 2026-10-20.
-type detail() :: #{
    provider => binary(),
    confidence => binary(),
    method => binary(),
    first_seen => binary(),
    last_seen => binary(),
    hits => integer(),
    hits_days_pct => integer(),
    providers_num => integer(),
    entry => boolean(),
    exit => boolean(),
    protocols => [binary()],
    num_ports => integer(),
    num_proxies => integer(),
    last_usable => binary()
}.

%% Where the address is, on every keyed answer: every key present, an empty
%% binary where nothing is known.
-type location() :: #{
    continent := binary(),
    continent_name := binary(),
    country := binary(),
    country_name := binary(),
    timezone := binary(),
    currency_code := binary(),
    currency_name := binary(),
    currency_symbol := binary(),
    flag_emoji := binary(),
    flag_unicode := binary()
}.

%% The AS announcing the address, on every keyed answer: `asn' is 0 and the rest
%% empty where no announcement covers it.
-type asn() :: #{
    asn := non_neg_integer(),
    name := binary(),
    domain := binary(),
    type := binary(),
    prefix := binary()
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

%% @doc The answer a bogon gets, in the full shape the API serves at its widest plan:
%% every flag false, every detail empty, and a location and AS of empty binaries
%% and AS 0.
%%
%% This is deliberately the WIDEST shape whatever your plan is, so a caller must
%% not infer which fields they are entitled to from a bogon answer.
%%
%% Built as a WIRE body and then mapped, so `raw' carries the same answer the
%% mapped keys do. An empty `raw' here would be a different shape from every
%% served answer, and anything reading the wire names - the middleware's block
%% condition does - would see a plan that serves nothing.
-spec bogon(binary()) -> result().
bogon(Ip) ->
    Wire = #{
        <<"ip">> => Ip,
        <<"is_vpn">> => false,
        <<"is_hosting">> => false,
        <<"is_relay">> => false,
        <<"is_tor">> => false,
        <<"is_cdn">> => false,
        <<"is_resproxy">> => false,
        <<"is_dcproxy">> => false,
        <<"is_mobproxy">> => false,
        <<"is_pubproxy">> => false,
        <<"vpn">> => #{},
        <<"hosting">> => #{},
        <<"relay">> => #{},
        <<"tor">> => #{},
        <<"cdn">> => #{},
        <<"resproxy">> => #{},
        <<"dcproxy">> => #{},
        <<"mobproxy">> => #{},
        <<"pubproxy">> => #{},
        <<"location">> => maps:from_keys(
            [<<"continent">>, <<"continent_name">>, <<"country">>, <<"country_name">>,
             <<"timezone">>, <<"currency_code">>, <<"currency_name">>, <<"currency_symbol">>,
             <<"flag_emoji">>, <<"flag_unicode">>],
            <<>>),
        <<"asn">> => #{<<"asn">> => 0, <<"name">> => <<>>, <<"domain">> => <<>>,
                       <<"type">> => <<>>, <<"prefix">> => <<>>}
    },
    (from_wire(Wire))#{is_bogon => true}.

%% Every nested object in a lookup response is a detail, the location or the AS,
%% so its keys go through the same allowlist as the top level.
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
key(<<"is_pubproxy">>) -> is_pubproxy;
key(<<"vpn">>) -> vpn;
key(<<"hosting">>) -> hosting;
key(<<"relay">>) -> relay;
key(<<"tor">>) -> tor;
key(<<"cdn">>) -> cdn;
key(<<"resproxy">>) -> resproxy;
key(<<"dcproxy">>) -> dcproxy;
key(<<"mobproxy">>) -> mobproxy;
key(<<"pubproxy">>) -> pubproxy;
key(<<"provider">>) -> provider;
key(<<"confidence">>) -> confidence;
key(<<"method">>) -> method;
key(<<"first_seen">>) -> first_seen;
key(<<"last_seen">>) -> last_seen;
key(<<"hits">>) -> hits;
key(<<"hits_days_pct">>) -> hits_days_pct;
key(<<"providers_num">>) -> providers_num;
key(<<"entry">>) -> entry;
key(<<"exit">>) -> exit;
key(<<"protocols">>) -> protocols;
key(<<"num_ports">>) -> num_ports;
key(<<"num_proxies">>) -> num_proxies;
key(<<"last_usable">>) -> last_usable;
key(<<"location">>) -> location;
key(<<"continent">>) -> continent;
key(<<"continent_name">>) -> continent_name;
key(<<"country">>) -> country;
key(<<"country_name">>) -> country_name;
key(<<"timezone">>) -> timezone;
key(<<"currency_code">>) -> currency_code;
key(<<"currency_name">>) -> currency_name;
key(<<"currency_symbol">>) -> currency_symbol;
key(<<"flag_emoji">>) -> flag_emoji;
key(<<"flag_unicode">>) -> flag_unicode;
key(<<"asn">>) -> asn;
key(<<"name">>) -> name;
key(<<"domain">>) -> domain;
key(<<"type">>) -> type;
key(<<"prefix">>) -> prefix;
key(Other) -> Other.
