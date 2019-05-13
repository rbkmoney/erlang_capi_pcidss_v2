-module(capi_real_handler).

-include_lib("dmsl/include/dmsl_payment_processing_thrift.hrl").
-include_lib("dmsl/include/dmsl_domain_thrift.hrl").
-include_lib("dmsl/include/dmsl_cds_thrift.hrl").
-include_lib("dmsl/include/dmsl_merch_stat_thrift.hrl").
-include_lib("dmsl/include/dmsl_webhooker_thrift.hrl").
-include_lib("dmsl/include/dmsl_user_interaction_thrift.hrl").
-include_lib("dmsl/include/dmsl_geo_ip_thrift.hrl").
-include_lib("dmsl/include/dmsl_reporting_thrift.hrl").
-include_lib("dmsl/include/dmsl_payment_tool_provider_thrift.hrl").

-include_lib("binbase_proto/include/binbase_binbase_thrift.hrl").

-behaviour(swag_server_logic_handler).

%% API callbacks
-export([authorize_api_key/2]).
-export([handle_request/3]).

%% @WARNING Must be refactored in case of different classes of users using this API
-define(REALM, <<"external">>).

-define(SWAG_HANDLER_SCOPE, swag_handler).

-define(DEFAULT_INVOICE_META, #{}).
-define(DEFAULT_INVOICE_TPL_META, #{}).
-define(DEFAULT_URL_LIFETIME, 60). % seconds

-define(payment_institution_ref(PaymentInstitutionID),
    #domain_PaymentInstitutionRef{id = PaymentInstitutionID}).

-define(CAPI_NS, <<"com.rbkmoney.capi">>).

-spec authorize_api_key(swag_server:operation_id(), swag_server:api_key()) ->
    Result :: false | {true, capi_auth:context()}.

authorize_api_key(OperationID, ApiKey) ->
    scoper:scope(?SWAG_HANDLER_SCOPE, #{operation_id => OperationID, api_key => ApiKey}, fun() ->
        _ = lager:debug("Api key authorization started"),
        case uac:authorize_api_key(ApiKey, get_verification_opts()) of
            {ok, Context} ->
                _ = lager:debug("Api key authorization successful"),
                {true, Context};
            {error, Error} ->
                _ = lager:info("Api key authorization failed due to ~p", [Error]),
                false
        end
    end).

get_verification_opts() ->
    #{}.

-type request_data() :: #{atom() | binary() => term()}.

-spec handle_request(
    OperationID :: swag_server:operation_id(),
    Req :: request_data(),
    Context :: swag_server:request_context()
) ->
    {ok | error, swag_server_logic_handler:response()}.

handle_request(OperationID, Req, Context) ->
    _ = lager:info("Processing request ~p", [OperationID]),
    try
        ok = scoper:add_scope(?SWAG_HANDLER_SCOPE, #{operation_id => OperationID}),
        OperationACL = capi_auth:get_operation_access(OperationID, Req),
        case uac:authorize_operation(OperationACL, get_auth_context(Context)) of
            ok ->
                ReqContext = create_context(Req, get_auth_context(Context)),
                process_request(OperationID, Req, Context, ReqContext);
            {error, _} = Error ->
                _ = lager:info("Operation ~p authorization failed due to ~p", [OperationID, Error]),
                {error, {401, [], general_error(<<"Unauthorized operation">>)}}
        end
    catch
        error:{woody_error, {Source, Class, Details}} ->
            process_woody_error(Source, Class, Details)
    after
        ok = scoper:remove_scope(?SWAG_HANDLER_SCOPE)
    end.

-spec process_request(
    OperationID :: swag_server:operation_id(),
    Req :: request_data(),
    Context :: swag_server:request_context(),
    ReqCtx :: woody_context:ctx()
) ->
    {Code :: non_neg_integer(), Headers :: [], Response :: #{}}.

process_request('CreatePaymentResource', Req, Context, ReqCtx) ->
    Params = maps:get('PaymentResourceParams', Req),
    ClientInfo = enrich_client_info(maps:get(<<"clientInfo">>, Params), Context),
    try
        V = maps:get(<<"paymentTool">>, Params),
        {PaymentTool, PaymentSessionID} = case V of
            #{<<"paymentToolType">> := <<"CardData">>} ->
                process_card_data(V, ReqCtx);
            #{<<"paymentToolType">> := <<"PaymentTerminalData">>} ->
                process_payment_terminal_data(V, ReqCtx);
            #{<<"paymentToolType">> := <<"DigitalWalletData">>} ->
                process_digital_wallet_data(V, ReqCtx);
            #{<<"paymentToolType">> := <<"TokenizedCardData">>} ->
                process_tokenized_card_data(V, ReqCtx)
        end,
        {ok, {201, [], decode_disposable_payment_resource(#domain_DisposablePaymentResource{
            payment_tool = PaymentTool,
            payment_session_id = PaymentSessionID,
            client_info = encode_client_info(ClientInfo)
        })}}
    catch
        Result ->
            Result
    end.

%%%

service_call(ServiceName, Function, Args, Context) ->
    capi_woody_client:call_service(ServiceName, Function, Args, Context).

create_context(#{'X-Request-ID' := RequestID}, AuthContext) ->
    RpcID = #{trace_id := TraceID} = woody_context:new_rpc_id(genlib:to_binary(RequestID)),
    ok = scoper:add_meta(#{request_id => RequestID, trace_id => TraceID}),
    woody_user_identity:put(collect_user_identity(AuthContext), woody_context:new(RpcID)).

collect_user_identity(AuthContext) ->
    genlib_map:compact(#{
        id => capi_auth:get_subject_id(AuthContext),
        realm => ?REALM,
        email => capi_auth:get_claim(<<"email">>, AuthContext, undefined),
        username => capi_auth:get_claim(<<"name">>, AuthContext, undefined)
    }).

logic_error(Code, Message) ->
    #{<<"code">> => genlib:to_binary(Code), <<"message">> => genlib:to_binary(Message)}.

general_error(Message) ->
    #{<<"message">> => genlib:to_binary(Message)}.

parse_exp_date(ExpDate) when is_binary(ExpDate) ->
    [Month, Year0] = binary:split(ExpDate, <<"/">>),
    Year = case genlib:to_int(Year0) of
        Y when Y < 100 ->
            2000 + Y;
        Y ->
            Y
    end,
    {genlib:to_int(Month), Year}.

get_auth_context(#{auth_context := AuthContext}) ->
    AuthContext.

get_peer_info(#{peer := Peer}) ->
    Peer.

decode_bank_card(#domain_BankCard{
    'token'  = Token,
    'payment_system' = PaymentSystem,
    'bin' = Bin,
    'masked_pan' = MaskedPan,
    'token_provider' = TokenProvider,
    'issuer_country' = IssuerCountry,
    'bank_name'      = BankName,
    'metadata'       = Metadata
}) ->
    capi_utils:map_to_base64url(genlib_map:compact(#{
        <<"type">> => <<"bank_card">>,
        <<"token">> => Token,
        <<"payment_system">> => PaymentSystem,
        <<"bin">> => Bin,
        <<"masked_pan">> => MaskedPan,
        <<"token_provider">> => TokenProvider,
        <<"issuer_country">> => IssuerCountry,
        <<"bank_name"     >> => BankName,
        <<"metadata"      >> => decode_bank_card_metadata(Metadata)
    })).

decode_bank_card_metadata(undefined) ->
    undefined;
decode_bank_card_metadata(Meta) ->
    maps:map(fun(_, Data) -> capi_msgp_marshalling:unmarshal(Data) end, Meta).

decode_payment_terminal(#domain_PaymentTerminal{
    terminal_type = Type
}) ->
    capi_utils:map_to_base64url(#{
        <<"type">> => <<"payment_terminal">>,
        <<"terminal_type">> => Type
    }).

decode_digital_wallet(#domain_DigitalWallet{
    provider = Provider,
    id = ID
}) ->
    capi_utils:map_to_base64url(#{
        <<"type">> => <<"digital_wallet">>,
        <<"provider">> => atom_to_binary(Provider, utf8),
        <<"id">> => ID
    }).

decode_client_info(ClientInfo) ->
    #{
        <<"fingerprint">> => ClientInfo#domain_ClientInfo.fingerprint,
        <<"ip">> => ClientInfo#domain_ClientInfo.ip_address
    }.

encode_client_info(ClientInfo) ->
    #domain_ClientInfo{
        fingerprint = maps:get(<<"fingerprint">>, ClientInfo),
        ip_address = maps:get(<<"ip">>, ClientInfo)
    }.

encode_content(json, Data) ->
    #'Content'{
        type = <<"application/json">>,
        data = jsx:encode(Data)
    }.

encode_residence(undefined) ->
    undefined;
encode_residence(Residence) when is_binary(Residence) ->
    try
        list_to_existing_atom(string:to_lower(binary_to_list(Residence)))
    catch
        error:badarg ->
            throw({encode_residence, invalid_residence})
    end.

decode_payment_tool_token({bank_card, BankCard}) ->
    decode_bank_card(BankCard);
decode_payment_tool_token({payment_terminal, PaymentTerminal}) ->
    decode_payment_terminal(PaymentTerminal);
decode_payment_tool_token({digital_wallet, DigitalWallet}) ->
    decode_digital_wallet(DigitalWallet).

decode_payment_tool_details({bank_card, V}) ->
    decode_bank_card_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsBankCard">>});
decode_payment_tool_details({payment_terminal, V}) ->
    decode_payment_terminal_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsPaymentTerminal">>});
decode_payment_tool_details({digital_wallet, V}) ->
    decode_digital_wallet_details(V, #{<<"detailsType">> => <<"PaymentToolDetailsDigitalWallet">>}).

decode_bank_card_details(BankCard, V) ->
    LastDigits = decode_last_digits(BankCard#domain_BankCard.masked_pan),
    Bin = BankCard#domain_BankCard.bin,
    merge_and_compact(V, #{
        <<"lastDigits">>     => LastDigits,
        <<"bin">>            => Bin,
        <<"cardNumberMask">> => decode_masked_pan(Bin, LastDigits),
        <<"paymentSystem" >> => genlib:to_binary(BankCard#domain_BankCard.payment_system),
        <<"tokenProvider" >> => decode_token_provider(BankCard#domain_BankCard.token_provider)
    }).

decode_token_provider(Provider) when Provider /= undefined ->
    genlib:to_binary(Provider);
decode_token_provider(undefined) ->
    undefined.

decode_payment_terminal_details(#domain_PaymentTerminal{
    terminal_type = Type
}, V) ->
    V#{
        <<"provider">> => genlib:to_binary(Type)
    }.

decode_digital_wallet_details(#domain_DigitalWallet{
    provider = qiwi,
    id = ID
}, V) ->
    V#{
        <<"digitalWalletDetailsType">> => <<"DigitalWalletDetailsQIWI">>,
        <<"phoneNumberMask">> => mask_phone_number(ID)
    }.

-define(MASKED_PAN_MAX_LENGTH, 4).

decode_last_digits(MaskedPan) when byte_size(MaskedPan) > ?MASKED_PAN_MAX_LENGTH ->
    binary:part(MaskedPan, {byte_size(MaskedPan), -?MASKED_PAN_MAX_LENGTH});
decode_last_digits(MaskedPan) ->
    MaskedPan.

-define(PAN_LENGTH, 16).

decode_masked_pan(Bin, LastDigits) ->
    Mask = binary:copy(<<"*">>, ?PAN_LENGTH - byte_size(Bin) - byte_size(LastDigits)),
    <<Bin/binary, Mask/binary, LastDigits/binary>>.

mask_phone_number(PhoneNumber) ->
    genlib_string:redact(PhoneNumber, <<"^\\+\\d(\\d{1,10}?)\\d{2,4}$">>).


process_woody_error(_Source, result_unexpected, _Details) ->
    {error, reply_5xx(500)};
process_woody_error(_Source, resource_unavailable, _Details) ->
    {error, reply_5xx(503)};
process_woody_error(_Source, result_unknown, _Details) ->
    {error, reply_5xx(504)}.

reply_5xx(Code) when Code >= 500 andalso Code < 600 ->
    {Code, [], <<>>}.

enrich_client_info(ClientInfo, Context) ->
    ClientInfo#{<<"ip">> => prepare_client_ip(Context)}.

prepare_client_ip(Context) ->
    #{ip_address := IP} = get_peer_info(Context),
    genlib:to_binary(inet:ntoa(IP)).

process_card_data(Data, ReqCtx) ->
    put_card_data_to_cds(encode_card_data(Data), encode_session_data(Data), ReqCtx).

put_card_data_to_cds(CardData, SessionData, ReqCtx) ->
    BinData = lookup_bank_info(CardData#'CardData'.pan, ReqCtx),
    case service_call(cds_storage, 'PutCardData', [CardData, SessionData], ReqCtx) of
        {ok, #'PutCardDataResult'{session_id = SessionID, bank_card = BankCard}} ->
            {{bank_card, expand_card_info(BankCard, BinData)}, SessionID};
        {exception, Exception} ->
            case Exception of
                #'InvalidCardData'{} ->
                    throw({ok, {400, [], logic_error(invalidRequest, <<"Card data is invalid">>)}});
                #'KeyringLocked'{} ->
                    % TODO
                    % It's better for the cds to signal woody-level unavailability when the
                    % keyring is locked, isn't it? It could always mention keyring lock as a
                    % reason in a woody error definition.
                    throw({error, reply_5xx(503)})
            end
    end.

lookup_bank_info(Pan, ReqCtx) ->
    RequestVersion = {'last', #binbase_Last{}},
    case service_call(binbase, 'Lookup', [Pan, RequestVersion], ReqCtx) of
        {ok, #'binbase_ResponseData'{bin_data = BinData, version = Version}} ->
            {BinData, Version};
        {exception, #'binbase_BinNotFound'{}} ->
            throw({ok, {400, [], logic_error(invalidRequest, <<"Card data is invalid">>)}})
    end.

expand_card_info(BankCard, {BinData, Version}) ->
    try
        BankCard#'domain_BankCard'{
            payment_system = encode_binbase_payment_system(BinData#'binbase_BinData'.payment_system),
            issuer_country = encode_residence(BinData#'binbase_BinData'.iso_country_code),
            bank_name = BinData#'binbase_BinData'.bank_name,
            metadata = #{
                ?CAPI_NS =>
                    {obj, #{
                        {str, <<"version">>} => {i, Version}
                    }
                }
            }
        }
    catch
        throw:{encode_binbase_payment_system, invalid_payment_system} ->
            throw({ok, {400, [], logic_error(invalidRequest, <<"Unsupported card">>)}});
        throw:{encode_residence, invalid_residence} ->
            throw({ok, {400, [], logic_error(invalidRequest, <<"Unsupported card">>)}})
    end.

encode_binbase_payment_system(<<"VISA">>)                      -> visa;
encode_binbase_payment_system(<<"VISA/DANKORT">>)              -> visa;         % supposedly 🤔
encode_binbase_payment_system(<<"MASTERCARD">>)                -> mastercard;
% encode_binbase_payment_system(<<"???">>)                       -> visaelectron;
encode_binbase_payment_system(<<"MAESTRO">>)                   -> maestro;
% encode_binbase_payment_system(<<"???">>)                       -> forbrugsforeningen;
encode_binbase_payment_system(<<"DANKORT">>)                   -> dankort;
encode_binbase_payment_system(<<"AMERICAN EXPRESS">>)          -> amex;
encode_binbase_payment_system(<<"DINERS CLUB INTERNATIONAL">>) -> dinersclub;
encode_binbase_payment_system(<<"DISCOVER">>)                  -> discover;
encode_binbase_payment_system(<<"UNIONPAY">>)                  -> unionpay;
encode_binbase_payment_system(<<"JCB">>)                       -> jcb;
encode_binbase_payment_system(<<"NSPK MIR">>)                  -> nspkmir;
encode_binbase_payment_system(_) ->
    throw({encode_binbase_payment_system, invalid_payment_system}).

encode_card_data(CardData) ->
    {Month, Year} = parse_exp_date(genlib_map:get(<<"expDate">>, CardData)),
    CardNumber = genlib:to_binary(genlib_map:get(<<"cardNumber">>, CardData)),
    #'CardData'{
        pan  = CardNumber,
        exp_date = #'ExpDate'{
            month = Month,
            year = Year
        },
        cardholder_name = genlib_map:get(<<"cardHolder">>, CardData)
    }.

encode_session_data(CardData) ->
    #'SessionData'{
        auth_data = {card_security_code, #'CardSecurityCode'{
            value = genlib_map:get(<<"cvv">>, CardData)
        }}
    }.

process_payment_terminal_data(Data, _ReqCtx) ->
    PaymentTerminal = #domain_PaymentTerminal{
        terminal_type = binary_to_existing_atom(
            genlib_map:get(<<"provider">>, Data),
            utf8
        )
    },
    {{payment_terminal, PaymentTerminal}, <<>>}.

process_digital_wallet_data(Data, _ReqCtx) ->
    DigitalWallet = case Data of
        #{<<"digitalWalletType">> := <<"DigitalWalletQIWI">>} ->
            #domain_DigitalWallet{
                provider = qiwi,
                id = maps:get(<<"phoneNumber">>, Data)
            }
    end,
    {{digital_wallet, DigitalWallet}, <<>>}.

process_tokenized_card_data(Data, ReqCtx) ->
    CallResult = service_call(
        get_token_provider_service_name(Data),
        'Unwrap',
        [encode_wrapped_payment_tool(Data)],
        ReqCtx
    ),
    UnwrappedPaymentTool = case CallResult of
        {ok, Tool} ->
            Tool;
        {exception, #'InvalidRequest'{}} ->
            throw({ok, {400, [], logic_error(invalidRequest, <<"Tokenized card data is invalid">>)}})
    end,
    process_put_card_data_result(
        put_card_data_to_cds(
            encode_tokenized_card_data(UnwrappedPaymentTool),
            encode_tokenized_session_data(UnwrappedPaymentTool),
            ReqCtx
        ),
        UnwrappedPaymentTool
    ).

encode_tokenized_session_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data = {tokenized_card, #paytoolprv_TokenizedCard{
        auth_data = {auth_3ds, #paytoolprv_Auth3DS{
            cryptogram = Cryptogram,
            eci = ECI
        }}
    }}
}) ->
    #'SessionData'{
        auth_data = {auth_3ds, #'Auth3DS'{
            cryptogram = Cryptogram,
            eci = ECI
        }}
    };
encode_tokenized_session_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data = {card, #paytoolprv_Card{}}
}) ->
    #'SessionData'{
        auth_data = {card_security_code, #'CardSecurityCode'{
            %% TODO dirty hack for test GooglePay card data
            value = <<"">>
        }}
    }.

encode_tokenized_card_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data = {tokenized_card, #paytoolprv_TokenizedCard{
        dpan = DPAN,
        exp_date = #paytoolprv_ExpDate{
            month = Month,
            year = Year
        }
    }},
    card_info = #paytoolprv_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    #'CardData'{
        pan  = DPAN,
        exp_date = #'ExpDate'{
            month = Month,
            year = Year
        },
        cardholder_name = CardholderName
    };
encode_tokenized_card_data(#paytoolprv_UnwrappedPaymentTool{
    payment_data = {card, #paytoolprv_Card{
        pan = PAN,
        exp_date = #paytoolprv_ExpDate{
            month = Month,
            year = Year
        }
    }},
    card_info = #paytoolprv_CardInfo{
        cardholder_name = CardholderName
    }
}) ->
    #'CardData'{
        pan  = PAN,
        exp_date = #'ExpDate'{
            month = Month,
            year = Year
        },
        cardholder_name = CardholderName
    }.

encode_wrapped_payment_tool(Data) ->
    #paytoolprv_WrappedPaymentTool{
        request = encode_payment_request(Data)
    }.

encode_payment_request(#{<<"provider" >> := <<"ApplePay">>} = Data) ->
    {apple, #paytoolprv_ApplePayRequest{
        merchant_id = maps:get(<<"merchantID">>, Data),
        payment_token = encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider" >> := <<"GooglePay">>} = Data) ->
    {google, #paytoolprv_GooglePayRequest{
        gateway_merchant_id = maps:get(<<"gatewayMerchantID">>, Data),
        payment_token = encode_content(json, maps:get(<<"paymentToken">>, Data))
    }};
encode_payment_request(#{<<"provider" >> := <<"SamsungPay">>} = Data) ->
    {samsung, #paytoolprv_SamsungPayRequest{
        service_id = genlib_map:get(<<"serviceID">>, Data),
        reference_id = genlib_map:get(<<"referenceID">>, Data)
    }}.

get_token_provider_service_name(Data) ->
    case Data of
        #{<<"provider">> := <<"ApplePay">>} ->
            payment_tool_provider_apple_pay;
        #{<<"provider">> := <<"GooglePay">>} ->
            payment_tool_provider_google_pay;
        #{<<"provider">> := <<"SamsungPay">>} ->
            payment_tool_provider_samsung_pay
    end.

process_put_card_data_result(
    {{bank_card, BankCard}, SessionID},
    #paytoolprv_UnwrappedPaymentTool{
        card_info = #paytoolprv_CardInfo{
            payment_system = PaymentSystem,
            last_4_digits  = Last4
        },
        payment_data = PaymentData,
        details = PaymentDetails
    }
) ->
    {
        {bank_card, BankCard#domain_BankCard{
            payment_system = PaymentSystem,
            masked_pan     = genlib:define(Last4, BankCard#domain_BankCard.masked_pan),
            token_provider = get_payment_token_provider(PaymentDetails, PaymentData)
        }},
        SessionID
    }.

decode_disposable_payment_resource(#domain_DisposablePaymentResource{
    payment_tool = PaymentTool,
    payment_session_id = PaymentSessionID,
    client_info = ClientInfo0
}) ->
    ClientInfo = decode_client_info(ClientInfo0),
    #{
        <<"paymentToolToken">> => decode_payment_tool_token(PaymentTool),
        <<"paymentSession">> => wrap_payment_session(ClientInfo, PaymentSessionID),
        <<"paymentToolDetails">> => decode_payment_tool_details(PaymentTool),
        <<"clientInfo">> => ClientInfo
    }.

merge_and_compact(M1, M2) ->
    genlib_map:compact(maps:merge(M1, M2)).

get_payment_token_provider(_PaymentDetails, {card, _}) ->
    % TODO
    % We deliberately hide the fact that we've got that payment tool from the likes of Google Chrome browser
    % in order to make our internal services think of it as if it was good ol' plain bank card. Without a
    % CVV though. A better solution would be to distinguish between a _token provider_ and an _origin_.
    undefined;

get_payment_token_provider({apple, _}, _PaymentData) ->
    applepay;
get_payment_token_provider({google, _}, _PaymentData) ->
    googlepay;
get_payment_token_provider({samsung, _}, _PaymentData) ->
    samsungpay.

wrap_payment_session(ClientInfo, PaymentSession) ->
    capi_utils:map_to_base64url(#{
        <<"clientInfo">> => ClientInfo,
        <<"paymentSession">> => PaymentSession
    }).

