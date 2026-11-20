%% @doc The wire body as an Erlang map, with absent and false kept apart.
%%
%% A key that is ABSENT from a result is one your plan does not include. It never
%% means "we could not check", so an absent key and `false' are genuinely
%% different answers, and `maps:get(is_hosting, Result, undefined)' is how you
%% tell them apart. `maps:get(is_hosting, Result, false)' is the reader for
%% callers who only care whether the address is flagged.
%%
%% A detail map that is present but empty (`#{}') means the flag above it is
%% false, as does an empty `web' list. A populated one always carries every one
%% of its keys.
-module(vpndetection_result).

-export([from_wire/1, bogon/1]).

-export_type([result/0, detail/0, location/0, asn/0, company/0, abuse/0]).

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
    is_anycast => boolean(),
    is_carrier => boolean(),
    is_satellite => boolean(),
    is_ssh => boolean(),
    is_smtp => boolean(),
    is_web => boolean(),
    is_dns_resolver => boolean(),
    is_bittorrent => boolean(),
    vpn => detail(),
    hosting => detail(),
    relay => detail(),
    tor => detail(),
    cdn => detail(),
    resproxy => detail(),
    dcproxy => detail(),
    mobproxy => detail(),
    pubproxy => detail(),
    carrier => detail(),
    satellite => detail(),
    ssh => detail(),
    smtp => detail(),
    %% A row per port that answered, lowest first, and `[]' when `is_web' is false.
    web => [detail()],
    dns_resolver => detail(),
    bittorrent => detail(),
    location => location(),
    asn => asn(),
    company => company(),
    %% The reverse DNS (PTR) name, an empty binary where the address has none.
    hostname => binary(),
    abuse => abuse(),
    %% On answers to a key on the free plan only: false while its organization's
    %% trial of every field lasts, true once the answer has Unlimited's.
    trial_expired => boolean(),
    %% On answers to a key on a paid plan only: false while the answer has every
    %% field, true once its organization's overage cap is reached and the answer
    %% has Unlimited's. Lookups answered past the cap are not billed.
    cap_reached => boolean()
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
    last_usable => binary(),
    %% The name the provider catalog gives the provider, beside the ID in
    %% `provider' to key on; an empty binary where the catalog names none or the
    %% range is unattributed.
    provider_name => binary(),
    %% The carrier, satellite, service and BitTorrent details, and a web row.
    name => binary(),
    mcc => binary(),
    mnc => binary(),
    country => binary(),
    orbit => binary(),
    segment => binary(),
    asn => integer(),
    port => integer(),
    banner => binary(),
    host_key_fp => binary(),
    session_ok => boolean(),
    tls_ok => boolean(),
    status_code => integer(),
    server => binary(),
    location => binary(),
    title => binary(),
    cert_subject_cn => binary(),
    cert_subject_o => binary(),
    cert_issuer_dn => binary(),
    cert_browser_trusted => boolean(),
    tls_version => binary(),
    recursion_available => boolean(),
    rcode => integer(),
    answer_correct => boolean(),
    verified => boolean(),
    id_matches_ip => boolean(),
    last_reachable => binary(),
    days_seen => integer(),
    peak_num_ports => integer(),
    indexer => boolean(),
    clients => [binary()]
}.

%% Where the address is, on every answer, with or without a key: every key
%% present, an empty binary where nothing is known. A paid plan adds the finer
%% keys, empty or 0 where nothing is known.
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
    flag_unicode := binary(),
    region => binary(),
    region_code => binary(),
    city => binary(),
    postal_code => binary(),
    latitude => number(),
    longitude => number(),
    accuracy_radius => integer(),
    geoname_id => binary(),
    dma_code => binary(),
    last_changed => binary()
}.

%% The AS announcing the address, on every answer, with or without a key: `asn'
%% is 0 and the rest empty where no announcement covers it.
-type asn() :: #{
    asn := non_neg_integer(),
    name := binary(),
    domain := binary(),
    type := binary(),
    prefix := binary(),
    country => binary(),
    rpki_status => binary()
}.

%% The organization the address is assigned to. Paid plans.
-type company() :: #{
    name := binary(),
    domain := binary(),
    type => binary(),
    country => binary()
}.

%% Who to report abuse from the address to. Paid plans.
-type abuse() :: #{
    email := binary(),
    name => binary(),
    phone => binary(),
    address => binary(),
    country => binary(),
    network => binary(),
    validated => boolean(),
    unvalidated_since => binary()
}.

%% @doc Translate a decoded response body into a result.
%%
%% Folding over what the body HAS is what preserves absent-versus-false: a key
%% the server did not send cannot appear in the fold, so no plan-gated member
%% can be invented as `false'.
-spec from_wire(map()) -> result().
from_wire(Body) when is_map(Body) ->
    Mapped = maps:fold(fun(K, V, Acc) -> Acc#{key(K) => value(V)} end, #{}, Body),
    Mapped#{is_bogon => maps:get(is_bogon, Mapped, false), raw => Body}.

%% @doc The answer a bogon gets, in the full shape the API serves at its widest plan:
%% `is_bogon' true and every other flag false, every detail empty, an empty `web'
%% list and hostname, and a location, AS, company and abuse contact with every
%% key an empty binary, 0 or false, as the API answers a bogon.
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
        <<"is_bogon">> => true,
        <<"is_vpn">> => false,
        <<"is_hosting">> => false,
        <<"is_relay">> => false,
        <<"is_tor">> => false,
        <<"is_cdn">> => false,
        <<"is_resproxy">> => false,
        <<"is_dcproxy">> => false,
        <<"is_mobproxy">> => false,
        <<"is_pubproxy">> => false,
        <<"is_anycast">> => false,
        <<"is_carrier">> => false,
        <<"is_satellite">> => false,
        <<"is_ssh">> => false,
        <<"is_smtp">> => false,
        <<"is_web">> => false,
        <<"is_dns_resolver">> => false,
        <<"is_bittorrent">> => false,
        <<"vpn">> => #{},
        <<"hosting">> => #{},
        <<"relay">> => #{},
        <<"tor">> => #{},
        <<"cdn">> => #{},
        <<"resproxy">> => #{},
        <<"dcproxy">> => #{},
        <<"mobproxy">> => #{},
        <<"pubproxy">> => #{},
        <<"carrier">> => #{},
        <<"satellite">> => #{},
        <<"ssh">> => #{},
        <<"smtp">> => #{},
        <<"web">> => [],
        <<"dns_resolver">> => #{},
        <<"bittorrent">> => #{},
        <<"location">> => (maps:from_keys(
            [<<"continent">>, <<"continent_name">>, <<"country">>, <<"country_name">>,
             <<"timezone">>, <<"currency_code">>, <<"currency_name">>, <<"currency_symbol">>,
             <<"flag_emoji">>, <<"flag_unicode">>, <<"region">>, <<"region_code">>, <<"city">>,
             <<"postal_code">>, <<"geoname_id">>, <<"dma_code">>, <<"last_changed">>],
            <<>>))#{<<"latitude">> => 0, <<"longitude">> => 0, <<"accuracy_radius">> => 0},
        <<"asn">> => #{<<"asn">> => 0, <<"name">> => <<>>, <<"domain">> => <<>>,
                       <<"type">> => <<>>, <<"prefix">> => <<>>, <<"country">> => <<>>,
                       <<"rpki_status">> => <<>>},
        <<"company">> => maps:from_keys([<<"name">>, <<"domain">>, <<"type">>, <<"country">>], <<>>),
        <<"hostname">> => <<>>,
        <<"abuse">> => (maps:from_keys(
            [<<"email">>, <<"name">>, <<"phone">>, <<"address">>, <<"country">>, <<"network">>,
             <<"unvalidated_since">>],
            <<>>))#{<<"validated">> => false}
    },
    from_wire(Wire).

%% Every nested object in a lookup response is a detail, the location, the AS,
%% the company or the abuse contact, and `web' is a list of rows, so their keys
%% go through the same allowlist as the top level.
value(V) when is_map(V) ->
    maps:fold(fun(K, DV, Acc) -> Acc#{key(K) => DV} end, #{}, V);
value(V) when is_list(V) ->
    [value(E) || E <- V];
value(V) ->
    V.

%% Only these names become atoms, and the set is fixed by the spec. Decoding a
%% server-supplied key straight to an atom is an atom table leak: the table is
%% never collected and is capped, so a response carrying arbitrary keys (which
%% the dataset metadata's `schema' and `sample' both do) would eventually take
%% the VM down. Anything unrecognized keeps its binary key.
key(<<"ip">>) -> ip;
key(<<"is_bogon">>) -> is_bogon;
key(<<"is_vpn">>) -> is_vpn;
key(<<"is_hosting">>) -> is_hosting;
key(<<"is_relay">>) -> is_relay;
key(<<"is_tor">>) -> is_tor;
key(<<"is_cdn">>) -> is_cdn;
key(<<"is_resproxy">>) -> is_resproxy;
key(<<"is_dcproxy">>) -> is_dcproxy;
key(<<"is_mobproxy">>) -> is_mobproxy;
key(<<"is_pubproxy">>) -> is_pubproxy;
key(<<"trial_expired">>) -> trial_expired;
key(<<"cap_reached">>) -> cap_reached;
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
key(<<"provider_name">>) -> provider_name;
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
key(<<"is_anycast">>) -> is_anycast;
key(<<"is_carrier">>) -> is_carrier;
key(<<"is_satellite">>) -> is_satellite;
key(<<"is_ssh">>) -> is_ssh;
key(<<"is_smtp">>) -> is_smtp;
key(<<"is_web">>) -> is_web;
key(<<"is_dns_resolver">>) -> is_dns_resolver;
key(<<"is_bittorrent">>) -> is_bittorrent;
key(<<"carrier">>) -> carrier;
key(<<"satellite">>) -> satellite;
key(<<"ssh">>) -> ssh;
key(<<"smtp">>) -> smtp;
key(<<"web">>) -> web;
key(<<"dns_resolver">>) -> dns_resolver;
key(<<"bittorrent">>) -> bittorrent;
key(<<"company">>) -> company;
key(<<"hostname">>) -> hostname;
key(<<"abuse">>) -> abuse;
key(<<"mcc">>) -> mcc;
key(<<"mnc">>) -> mnc;
key(<<"orbit">>) -> orbit;
key(<<"segment">>) -> segment;
key(<<"port">>) -> port;
key(<<"banner">>) -> banner;
key(<<"host_key_fp">>) -> host_key_fp;
key(<<"session_ok">>) -> session_ok;
key(<<"tls_ok">>) -> tls_ok;
key(<<"status_code">>) -> status_code;
key(<<"server">>) -> server;
key(<<"title">>) -> title;
key(<<"cert_subject_cn">>) -> cert_subject_cn;
key(<<"cert_subject_o">>) -> cert_subject_o;
key(<<"cert_issuer_dn">>) -> cert_issuer_dn;
key(<<"cert_browser_trusted">>) -> cert_browser_trusted;
key(<<"tls_version">>) -> tls_version;
key(<<"recursion_available">>) -> recursion_available;
key(<<"rcode">>) -> rcode;
key(<<"answer_correct">>) -> answer_correct;
key(<<"verified">>) -> verified;
key(<<"id_matches_ip">>) -> id_matches_ip;
key(<<"last_reachable">>) -> last_reachable;
key(<<"days_seen">>) -> days_seen;
key(<<"peak_num_ports">>) -> peak_num_ports;
key(<<"indexer">>) -> indexer;
key(<<"clients">>) -> clients;
key(<<"region">>) -> region;
key(<<"region_code">>) -> region_code;
key(<<"city">>) -> city;
key(<<"postal_code">>) -> postal_code;
key(<<"latitude">>) -> latitude;
key(<<"longitude">>) -> longitude;
key(<<"accuracy_radius">>) -> accuracy_radius;
key(<<"geoname_id">>) -> geoname_id;
key(<<"dma_code">>) -> dma_code;
key(<<"last_changed">>) -> last_changed;
key(<<"rpki_status">>) -> rpki_status;
key(<<"email">>) -> email;
key(<<"phone">>) -> phone;
key(<<"address">>) -> address;
key(<<"network">>) -> network;
key(<<"validated">>) -> validated;
key(<<"unvalidated_since">>) -> unvalidated_since;
key(Other) -> Other.
