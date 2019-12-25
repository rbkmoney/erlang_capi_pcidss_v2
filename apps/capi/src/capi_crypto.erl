-module(capi_crypto).

-type payment_tool_token() :: capi_handler_encoder:payment_tool_token().
-type encrypted_token() :: binary().

-export_type([encrypted_token/0]).

-export([encrypt_payment_tool_token/2]).

-spec encrypt_payment_tool_token(binary(), payment_tool_token()) ->
    encrypted_token().

encrypt_payment_tool_token(IdempotentKey, PaymentToolToken) ->
    EncryptionParams = create_encryption_params(IdempotentKey),
    ThriftType = {struct, union, {dmsl_payment_tool_token_thrift, 'PaymentToolToken'}},
    {ok, EncodedToken} = lechiffre:encode(ThriftType, PaymentToolToken, EncryptionParams),
    TokenVersion = payment_tool_token_version(),
    base64url:encode(<<TokenVersion/binary, EncodedToken/binary>>).

%% Internal

payment_tool_token_version() ->
    <<"v1">>.

create_encryption_params(IdempotentKey) ->
    #{iv => lechiffre:create_iv(IdempotentKey)}.
