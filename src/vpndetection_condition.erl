%% @doc Deciding whether an answer is worth blocking.
%%
%% A condition is written in the shape of a served answer and keyed by the same
%% names the API uses, so what you write here reads like what you get back.
%% Atom and binary keys both work, which is what lets a condition come out of
%% `json:decode/1' on an app's config file as readily as out of source:
%%
%% ```
%% #{is_vpn => true}
%% #{is_vpn => true, vpn => #{provider => <<"nordvpn">>}}
%% #{is_resproxy => true, resproxy => #{hits => #{gte => 5}}}
%% #{vpn => #{confidence => [<<"high">>, <<"medium">>]}}
%% [#{is_tor => true}, #{is_resproxy => true}]   % a list is OR
%% '''
%%
%% A value may be a scalar (equality, strings without regard to case), a list
%% meaning any-of, a map of `gte'/`gt'/`lte'/`lt' bounding a number, or a nested
%% condition. A member set to `false', `null' or `undefined' is ignored entirely
%% - a condition states the positive signals you act on, so there is no way to
%% write "block when this is false", which would otherwise read as blocking
%% everybody.
%%
%% WRITE STRINGS AS BINARIES. An Erlang string is a list of codepoints, so
%% `"nordvpn"' and an any-of of those numbers are the same term and no library
%% can tell them apart. A bare string is accepted anyway - `io_lib' decides,
%% exactly as it does when printing - but that makes an any-of of small
%% printable integers unreachable. Binaries have no such ambiguity, and are what
%% `json:decode/1' produces.
-module(vpndetection_condition).

-export([matches/2, missing_members/2, validate/1, constraint_count/1]).

-export_type([condition/0, conditions/0]).

-type condition() :: #{atom() | binary() => term()}.
-type conditions() :: condition() | [condition()].

-define(BOUND_KEYS, [<<"gte">>, <<"gt">>, <<"lte">>, <<"lt">>]).

%% @doc Whether an answer satisfies the condition, and should therefore be blocked.
-spec matches(conditions(), vpndetection_result:result()) -> boolean().
matches(Condition, Result) ->
    Raw = maps:get(raw, Result, #{}),
    lists:any(fun(One) -> matches_object(One, Raw) end, wrap(Condition)).

%% @doc The top-level members a condition names that this answer did not carry.
%%
%% A field your plan does not include is absent rather than false, so a condition
%% naming one can never match and the block would silently never fire. Gating is
%% per top-level member, which is why only the first path segment is checked: a
%% detail object present but empty is a real answer meaning the flag is false,
%% not a plan gap.
%%
%% A locally answered bogon needs no special case: it is synthesized in the
%% widest shape, so every member is present and nothing reads as missing.
-spec missing_members(conditions(), vpndetection_result:result()) -> [binary()].
missing_members(Condition, Result) ->
    Raw = maps:get(raw, Result, #{}),
    lists:foldl(
        fun(One, Acc) ->
            maps:fold(
                fun(Member, Want, Inner) ->
                    Name = key(Member),
                    case constraint_count(Want) =:= 0
                        orelse lists:member(Name, Inner)
                        orelse maps:is_key(Name, Raw)
                    of
                        true -> Inner;
                        false -> Inner ++ [Name]
                    end
                end,
                Acc,
                One
            )
        end,
        [],
        wrap(Condition)
    ).

%% @doc Refuse a condition that constrains nothing.
%%
%% Ignoring `false' means `#{is_vpn => false}' and `#{}' have no terms left to
%% satisfy, so they would match every answer and block all traffic. Nobody
%% writes that on purpose, and failing when the middleware is built beats
%% discovering it in production.
-spec validate(conditions() | undefined) -> ok | {error, {constrains_nothing, condition()}}.
validate(undefined) ->
    ok;
validate(Condition) ->
    case lists:dropwhile(fun(One) -> constraint_count(One) > 0 end, wrap(Condition)) of
        [] -> ok;
        [Empty | _] -> {error, {constrains_nothing, Empty}}
    end.

%% @doc How many leaf constraints a condition actually carries.
-spec constraint_count(term()) -> non_neg_integer().
constraint_count(undefined) -> 0;
constraint_count(null) -> 0;
constraint_count(false) -> 0;
constraint_count(Value) when is_map(Value) ->
    case is_bound(Value) of
        true -> 1;
        false -> lists:sum([constraint_count(V) || V <- maps:values(Value)])
    end;
constraint_count(Value) when is_list(Value) ->
    case is_string(Value) of
        true -> 1;
        false -> lists:sum([constraint_count(V) || V <- Value])
    end;
constraint_count(_) -> 1.

wrap(Condition) when is_map(Condition) -> [Condition];
wrap(Condition) when is_list(Condition) -> Condition.

matches_object(Condition, Value) when is_map(Condition) ->
    maps:fold(
        fun
            (_Member, _Want, false) ->
                false;
            (Member, Want, true) ->
                constraint_count(Want) =:= 0
                    orelse matches_value(Want, member(key(Member), Value))
        end,
        true,
        Condition
    ).

%% An ABSENT member arrives here as the `absent' marker, which is exactly what
%% "not in your plan" looks like. Every clause below must therefore reject it,
%% which is what makes an unserved member fail a match rather than pass it. A
%% bare `undefined' would be ambiguous: it is also a value a caller can write.
member(Name, Value) when is_map(Value) -> maps:get(Name, Value, absent);
member(_Name, _Value) -> absent.

matches_value(_Want, absent) ->
    false;
%% Reachable only inside an any-of, since a bare one is dropped by its zero
%% constraint count. It is a term that was written to be ignored, so it matches
%% nothing rather than comparing as the atom it happens to be.
matches_value(Want, _Got) when Want =:= undefined; Want =:= null ->
    false;
matches_value(Want, Got) when is_map(Want) ->
    case is_bound(Want) of
        true -> matches_bound(Want, Got);
        false -> is_map(Got) andalso matches_object(Want, Got)
    end;
matches_value(Want, Got) when is_list(Want) ->
    case is_string(Want) of
        %% A string written as a list rather than a binary, which is what a
        %% caller who typed "nordvpn" without the sigil produces.
        true -> matches_value(list_to_binary(Want), Got);
        false -> lists:any(fun(Entry) -> matches_value(Entry, Got) end, Want)
    end;
matches_value(Want, Got) when is_binary(Want) ->
    %% Providers are lowercase slugs on the wire and a caller should not have to
    %% know that, so a string compares without case.
    is_binary(Got) andalso string:equal(Want, Got, true);
matches_value(Want, Got) when is_atom(Want), Want =/= true, Want =/= false ->
    matches_value(atom_to_binary(Want, utf8), Got);
matches_value(Want, Got) when is_number(Want) ->
    is_number(Got) andalso Want == Got;
matches_value(Want, Got) ->
    Want =:= Got.

matches_bound(Bound, Got) when is_number(Got) ->
    maps:fold(
        fun
            (_Key, _Limit, false) -> false;
            (Key, Limit, true) -> holds(key(Key), Got, Limit)
        end,
        true,
        Bound
    );
matches_bound(_Bound, _Got) ->
    false.

holds(<<"gte">>, Got, Limit) -> Got >= Limit;
holds(<<"gt">>, Got, Limit) -> Got > Limit;
holds(<<"lte">>, Got, Limit) -> Got =< Limit;
holds(<<"lt">>, Got, Limit) -> Got < Limit.

is_bound(Value) when is_map(Value) ->
    map_size(Value) > 0
        andalso lists:all(
            fun(K) -> lists:member(key(K), ?BOUND_KEYS) end, maps:keys(Value)
        ).

%% See the module doc: this is the ambiguity binaries avoid. `io_lib' is the
%% same judge the shell uses to decide whether to print a list as "abc" or as
%% [97,98,99], so a caller who has seen one has seen the other.
is_string([]) -> false;
is_string(Value) -> io_lib:printable_unicode_list(Value).

key(Key) when is_binary(Key) -> Key;
key(Key) when is_atom(Key) -> atom_to_binary(Key, utf8);
key(Key) when is_list(Key) -> list_to_binary(Key).
