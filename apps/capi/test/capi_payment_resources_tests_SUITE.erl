-module(capi_payment_resources_tests_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("dmsl/include/dmsl_domain_config_thrift.hrl").
-include_lib("dmsl/include/dmsl_payment_processing_thrift.hrl").
-include_lib("dmsl/include/dmsl_payment_processing_errors_thrift.hrl").
-include_lib("dmsl/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("binbase_proto/include/binbase_binbase_thrift.hrl").
-include_lib("dmsl/include/dmsl_cds_thrift.hrl").
-include_lib("capi_dummy_data.hrl").
-include_lib("jose/include/jose_jwk.hrl").

-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).
-export([init_per_testcase/2]).
-export([end_per_testcase/2]).

-export([init/1]).

-export([
    create_visa_payment_resource_ok_test/1,
    create_visa_with_empty_cvv_ok_test/1,
    create_nspkmir_payment_resource_ok_test/1,
    create_euroset_payment_resource_ok_test/1,
    create_qw_payment_resource_ok_test/1,
    create_applepay_tokenized_payment_resource_ok_test/1,
    create_googlepay_tokenized_payment_resource_ok_test/1,
    create_googlepay_plain_payment_resource_ok_test/1,

    authorization_positive_lifetime_ok_test/1,
    authorization_unlimited_lifetime_ok_test/1,
    authorization_far_future_deadline_ok_test/1,
    authorization_error_no_header_test/1,
    authorization_error_no_permission_test/1,
    authorization_bad_token_error_test/1
]).

-define(CAPI_PORT                   , 8080).
-define(CAPI_HOST_NAME              , "localhost").
-define(CAPI_URL                    , ?CAPI_HOST_NAME ++ ":" ++ integer_to_list(?CAPI_PORT)).

-define(TEST_PAYMENT_TOOL_ARGS, #{
    <<"paymentTool">> => #{
        <<"paymentToolType">> => <<"CardData">>,
        <<"cardNumber">> => <<"4111111111111111">>,
        <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
        <<"expDate">> => <<"08/27">>,
        <<"cvv">> => <<"232">>
    },
    <<"clientInfo">> => #{<<"fingerprint">> => <<"test fingerprint">>}
}).

-define(badresp(Code), {error, {Code, #{}}}).

-type test_case_name()  :: atom().
-type config()          :: [{atom(), any()}].
-type group_name()      :: atom().

-behaviour(supervisor).

-spec init([]) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.
init([]) ->
    {ok, {#{strategy => one_for_all, intensity => 1, period => 1}, []}}.

-spec all() ->
    [test_case_name()].
all() ->
    [
        {group, payment_resources}
    ].

-spec groups() ->
    [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {payment_resources, [],
            [
                create_visa_payment_resource_ok_test,
                create_visa_with_empty_cvv_ok_test,
                create_nspkmir_payment_resource_ok_test,
                create_euroset_payment_resource_ok_test,
                create_qw_payment_resource_ok_test,
                create_applepay_tokenized_payment_resource_ok_test,
                create_googlepay_tokenized_payment_resource_ok_test,
                create_googlepay_plain_payment_resource_ok_test,

                authorization_positive_lifetime_ok_test,
                authorization_unlimited_lifetime_ok_test,
                authorization_far_future_deadline_ok_test,
                authorization_error_no_header_test,
                authorization_error_no_permission_test,
                authorization_bad_token_error_test
            ]
        }
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    C = capi_ct_helper:init_suite(?MODULE, Config),
    {ok, Token} = capi_ct_helper:issue_token([{[payment_resources], write}], unlimited),
    [{context, capi_ct_helper:get_context(Token)} | C].

-spec end_per_suite(config()) ->
    _.
end_per_suite(C) ->
    _ = capi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    [application:stop(App) || App <- proplists:get_value(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) ->
    config().

init_per_group(_, Config) ->
    Config.

-spec end_per_group(group_name(), config()) ->
    _.
end_per_group(_Group, _C) ->
    ok.

-spec init_per_testcase(test_case_name(), config()) ->
    config().
init_per_testcase(_Name, C) ->
    [{test_sup, capi_ct_helper:start_mocked_service_sup(?MODULE)} | C].

-spec end_per_testcase(test_case_name(), config()) ->
    config().
end_per_testcase(_Name, C) ->
    capi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec create_visa_payment_resource_ok_test(_) ->
    _.
create_visa_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutCardData', [
                #'CardData'{pan = <<"411111", _:6/binary, Mask:4/binary>>},
                #'SessionData'{
                    auth_data = {card_security_code, #'CardSecurityCode'{
                        value = <<"232">>
                    }}
                }
            ]) ->
                {ok, #'PutCardDataResult'{
                    bank_card = #domain_BankCard{
                        token = ?STRING,
                        payment_system = visa,
                        bin = <<"411111">>,
                        masked_pan = Mask
                    },
                    session_id = ?STRING
                }}
        end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"visa">>,
        <<"lastDigits">> := <<"1111">>,
        <<"bin">> := <<"411111">>,
        <<"cardNumberMask">> := <<"411111******1111">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_visa_with_empty_cvv_ok_test(_) ->
    _.
create_visa_with_empty_cvv_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutCardData', [
                #'CardData'{pan = <<"411111", _:6/binary, Mask:4/binary>>},
                #'SessionData'{
                    auth_data = {card_security_code, #'CardSecurityCode'{
                        value = <<>>
                    }}
                }
            ]) ->
                {ok, #'PutCardDataResult'{
                    bank_card = #domain_BankCard{
                        token = ?STRING,
                        payment_system = visa,
                        bin = <<"411111">>,
                        masked_pan = Mask
                    },
                    session_id = ?STRING
                }}
        end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"visa">>,
        <<"lastDigits">> := <<"1111">>,
        <<"bin">> := <<"411111">>,
        <<"cardNumberMask">> := <<"411111******1111">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_nspkmir_payment_resource_ok_test(_) ->
    _.
create_nspkmir_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutCardData', [
                #'CardData'{pan = <<"22001111", _:6/binary, Mask:2/binary>>},
                #'SessionData'{
                    auth_data = {card_security_code, #'CardSecurityCode'{
                        value = <<"232">>
                    }}
                }
            ]) ->
                {ok, #'PutCardDataResult'{
                    bank_card = #domain_BankCard{
                        token = ?STRING,
                        payment_system = nspkmir,
                        bin = <<"22001111">>,
                        masked_pan = Mask
                    },
                    session_id = ?STRING
                }}
        end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"NSPK MIR">>)} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsBankCard">>,
        <<"paymentSystem">> := <<"nspkmir">>,
        <<"cardNumberMask">> := <<"22001111******11">>,
        <<"lastDigits">> := <<"11">>,
        <<"bin">> := <<"22001111">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"2200111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"08/27">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_euroset_payment_resource_ok_test(_) ->
    _.
create_euroset_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsPaymentTerminal">>,
        <<"provider">> := <<"euroset">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"PaymentTerminalData">>,
            <<"provider">> => <<"euroset">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_qw_payment_resource_ok_test(_) ->
    _.
create_qw_payment_resource_ok_test(Config) ->
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"detailsType">> := <<"PaymentToolDetailsDigitalWallet">>,
        <<"digitalWalletDetailsType">> := <<"DigitalWalletDetailsQIWI">>,
        <<"phoneNumberMask">> := <<"+7******3210">>
    }}} = capi_client_tokens:create_payment_resource(?config(context, Config), #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"DigitalWalletData">>,
            <<"digitalWalletType">> => <<"DigitalWalletQIWI">>,
            <<"phoneNumber">> => <<"+79876543210">>
        },
        <<"clientInfo">> => ClientInfo
    }).

-spec create_applepay_tokenized_payment_resource_ok_test(_) ->
    _.
create_applepay_tokenized_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_apple_pay, fun('Unwrap', _) -> {ok, ?UNWRAPPED_PAYMENT_TOOL(?APPLE_PAY_DETAILS)} end},
        {cds_storage, fun('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{<<"paymentSystem">> := <<"mastercard">>}}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"ApplePay">>,
                <<"merchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }).

-spec create_googlepay_tokenized_payment_resource_ok_test(_) ->
    _.
create_googlepay_tokenized_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_google_pay, fun('Unwrap', _) -> {ok, ?UNWRAPPED_PAYMENT_TOOL(?GOOGLE_PAY_DETAILS)} end},
        {cds_storage, fun('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end}
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := #{
        <<"paymentSystem">> := <<"mastercard">>,
        <<"tokenProvider">> := <<"googlepay">>
    }}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }).

-spec create_googlepay_plain_payment_resource_ok_test(_) ->
    _.
create_googlepay_plain_payment_resource_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {payment_tool_provider_google_pay,
            fun('Unwrap', _) ->
                {ok, ?UNWRAPPED_PAYMENT_TOOL(
                    ?GOOGLE_PAY_DETAILS,
                    {card, #paytoolprv_Card{
                        pan = <<"1234567890123456">>,
                        exp_date = #paytoolprv_ExpDate{month = 10, year = 2018}
                    }}
                )}
            end
        },
        {cds_storage,
            fun('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end
        },
        {binbase,
            fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT} end
        }
    ], Config),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    {ok, #{<<"paymentToolDetails">> := Details = #{<<"paymentSystem">> := <<"mastercard">>}}} =
        capi_client_tokens:create_payment_resource(?config(context, Config), #{
            <<"paymentTool">> => #{
                <<"paymentToolType">> => <<"TokenizedCardData">>,
                <<"provider">> => <<"GooglePay">>,
                <<"gatewayMerchantID">> => <<"SomeMerchantID">>,
                <<"paymentToken">> => #{}
            },
            <<"clientInfo">> => ClientInfo
        }),
    false = maps:is_key(<<"tokenProvider">>, Details).

%%

-spec authorization_positive_lifetime_ok_test(config()) ->
    _.
authorization_positive_lifetime_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun ('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    {ok, Token} = capi_ct_helper:issue_token([{[payment_resources], write}], {lifetime, 10}),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_unlimited_lifetime_ok_test(config()) ->
    _.
authorization_unlimited_lifetime_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun ('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    {ok, Token} = capi_ct_helper:issue_token([{[payment_resources], write}], unlimited),
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_far_future_deadline_ok_test(config()) ->
    _.
authorization_far_future_deadline_ok_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun ('PutCardData', _) -> {ok, ?PUT_CARD_DATA_RESULT} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    {ok, Token} = capi_ct_helper:issue_token([{[payment_resources], write}], {deadline, 4102444800}), % 01/01/2100 @ 12:00am (UTC)
    {ok, _} = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_header_test(config()) ->
    _.
authorization_error_no_header_test(_Config) ->
    Token = <<>>,
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_error_no_permission_test(config()) ->
    _.
authorization_error_no_permission_test(_Config) ->
    {ok, Token} = capi_ct_helper:issue_token([{[payment_resources], read}], {lifetime, 10}),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

-spec authorization_bad_token_error_test(config()) ->
    _.
authorization_bad_token_error_test(Config) ->
    {ok, Token} = issue_dummy_token([{[payment_resources], write}], Config),
    ?badresp(401) = capi_client_tokens:create_payment_resource(
        capi_ct_helper:get_context(Token),
        ?TEST_PAYMENT_TOOL_ARGS
    ).

%%

issue_dummy_token(ACL, Config) ->
    Claims = #{
        <<"jti">> => unique_id(),
        <<"sub">> => <<"TEST">>,
        <<"exp">> => 0,
        <<"resource_access">> => #{
            <<"common-api">> => #{
                <<"roles">> => capi_acl:encode(capi_acl:from_list(ACL))
            }
        }
    },
    BadPemFile = get_keysource("keys/local/dummy.pem", Config),
    BadJWK = jose_jwk:from_pem_file(BadPemFile),
    GoodPemFile = get_keysource("keys/local/private.pem", Config),
    GoodJWK = jose_jwk:from_pem_file(GoodPemFile),
    JWKPublic = jose_jwk:to_public(GoodJWK),
    {_Module, PublicKey} = JWKPublic#jose_jwk.kty,
    {_PemEntry, Data, _} = public_key:pem_entry_encode('SubjectPublicKeyInfo', PublicKey),
    KID = base64url:encode(crypto:hash(sha256, Data)),
    JWT = jose_jwt:sign(BadJWK, #{<<"alg">> => <<"RS256">>, <<"kid">> => KID}, Claims),
    {_Modules, Token} = jose_jws:compact(JWT),
    {ok, Token}.

get_keysource(Key, Config) ->
    filename:join(?config(data_dir, Config), Key).

unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).