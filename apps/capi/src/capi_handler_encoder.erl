-module(capi_handler_encoder).

-include_lib("damsel/include/dmsl_domain_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_token_thrift.hrl").

-export([encode_client_info/1]).
-export([encode_content/2]).
-export([encode_payment_tool_token/1]).

-export_type([encode_data/0]).
-export_type([payment_tool_token/0]).

-type request_data() :: capi_handler:request_data().
-type encode_data()  :: tuple().
-type payment_tool() :: dmsl_domain_thrift:'PaymentTool'().
-type payment_tool_token() :: dmsl_payment_tool_token_thrift:'PaymentToolToken'().

-spec encode_client_info(request_data()) ->
    encode_data().
encode_client_info(ClientInfo) ->
    #domain_ClientInfo{
        fingerprint = maps:get(<<"fingerprint">>, ClientInfo),
        ip_address  = maps:get(<<"ip"         >>, ClientInfo)
    }.

-spec encode_content(json, term()) ->
    encode_data().

encode_content(json, Data) ->
    #'Content'{
        type = <<"application/json">>,
        data = jsx:encode(Data)
    }.

-spec encode_payment_tool_token(payment_tool()) ->
    payment_tool_token().

encode_payment_tool_token({bank_card, BankCard}) ->
    {bank_card_payload, #ptt_BankCardPayload{
        bank_card = BankCard
    }};
encode_payment_tool_token({payment_terminal, PaymentTerminal}) ->
    {payment_terminal_payload, #ptt_PaymentTerminalPayload{
        payment_terminal = PaymentTerminal
    }};
encode_payment_tool_token({digital_wallet, DigitalWallet}) ->
    {digital_wallet_payload, #ptt_DigitalWalletPayload{
        digital_wallet = DigitalWallet
    }};
encode_payment_tool_token({crypto_currency, CryptoCurrency}) ->
    {crypto_currency_payload, #ptt_CryptoCurrencyPayload{
        crypto_currency = CryptoCurrency
    }};
encode_payment_tool_token({mobile_commerce, MobileCommerce}) ->
    {mobile_commerce_payload, #ptt_MobileCommercePayload {
        mobile_commerce = MobileCommerce
    }}.
