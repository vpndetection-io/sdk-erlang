%% The published package's `oauth_*' functions against the staging authorization
%% server, on a client built with NO key. Only what is safe to repeat: discovery,
%% a revoke and an exchange of junk, and at most ONE device authorization per run,
%% which nobody approves and which is never polled.
-module(oauth_integration_tests).

-include_lib("eunit/include/eunit.hrl").

%% The one client ID the server holds, already public in the CLI's source.
-define(CLIENT_ID, <<"vpndetection-cli">>).
-define(SINCE, [3, 2, 0]).

metadata_names_the_host_it_was_asked_on_test_() ->
    since(fun(Client) ->
        {ok, Metadata} = vpndetection:oauth_metadata(Client),

        ?assertEqual(staging_fixtures:staging(), maps:get(issuer, Metadata)),
        ?assert(maps:is_key(device_authorization_endpoint, Metadata)),
        ?assert(lists:member(<<"S256">>, maps:get(code_challenge_methods_supported, Metadata)))
    end).

revoking_junk_succeeds_test_() ->
    since(fun(Client) ->
        ?assertEqual(ok, vpndetection:oauth_revoke(Client, ?CLIENT_ID, <<"mo_rt_sdk-ci-not-a-token">>))
    end).

exchanging_an_unknown_device_code_is_an_expired_token_test_() ->
    since(fun(Client) ->
        Junk = <<"mo_dc_sdk-ci-not-a-code">>,
        ?assertMatch({error, #{error_code := <<"expired_token">>, status := 400}},
                     vpndetection:oauth_exchange_device_code(Client, ?CLIENT_ID, Junk))
    end).

%% 30 a minute per source address, shared by every SDK's run, so a slow_down is a
%% pass: it is the server answering this request correctly.
one_device_authorization_starts_a_sign_in_test_() ->
    since(fun(Client) ->
        case vpndetection:oauth_device_authorization(Client, ?CLIENT_ID, #{scope => <<"account.read">>}) of
            {error, Error} ->
                ?assertMatch(#{error_code := <<"slow_down">>}, Error);
            {ok, Device} ->
                #{device_code := Code, user_code := User, verification_uri := Uri,
                  expires_in := ExpiresIn, interval := Interval} = Device,
                ?assertNotEqual(<<>>, Code),
                ?assertNotEqual(<<>>, User),
                ?assertEqual(<<"/device">>, binary:part(Uri, byte_size(Uri) - 7, 7)),
                ?assert(ExpiresIn > 0),
                ?assert(Interval > 0)
        end
    end).

%% Gated on the INSTALLED version rather than on whether the function exists,
%% which would also skip quietly if one were ever removed.
since(Body) ->
    {timeout, 60, fun() ->
        _ = application:load(vpndetection),
        {ok, Vsn} = application:get_key(vpndetection, vsn),
        Installed = [list_to_integer(Part) || Part <- string:tokens(Vsn, ".")],
        case Installed >= ?SINCE of
            true ->
                Client = vpndetection:new(#{base_url => staging_fixtures:staging()}),
                try Body(Client) after vpndetection:close(Client) end;
            false ->
                staging_tiers:notice("SKIPPED: the oauth functions arrived in 3.2.0, and " ++ Vsn
                                     ++ " is installed")
        end
    end}.
