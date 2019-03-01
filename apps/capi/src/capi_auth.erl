-module(capi_auth).

-export([issue_access_token/2]).
-export([get_subject_id/1]).
-export([get_claims/1]).
-export([get_claim/2]).
-export([get_claim/3]).
-export([get_consumer/1]).
-export([get_operation_access/2]).

-type consumer() :: client | merchant | provider.

%% TODO
%% Hardcode for now, should pass it here probably as an argument
-define(DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME, 259200).
-define(DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME, 259200).

-type token_spec() ::
      {invoice    , InvoiceID    :: binary()}
    | {invoice_tpl, InvoiceTplID :: binary()}
    | {customer   , CustomerID   :: binary()}
.

-spec issue_access_token(PartyID :: binary(), token_spec()) ->
    uac_authorizer_jwt:token().
issue_access_token(PartyID, TokenSpec) ->
    {Claims, ACL, Expiration} = resolve_token_spec(TokenSpec),
    UniqueId = get_unique_id(),
    genlib:unwrap(
        uac_authorizer_jwt:issue(
            UniqueId,
            Expiration,
            {PartyID, uac_acl:from_list(ACL)},
            Claims,
            capi_pcidss
        )
    ).

-type acl() :: [{uac_acl:scope(), uac_acl:permission()}].

-spec resolve_token_spec(token_spec()) ->
    {uac:claims(), acl(), uac_authorizer_jwt:expiration()}.
resolve_token_spec({invoice, InvoiceID}) ->
    Claims =
        #{
            <<"cons">> => <<"client">> % token consumer
        },
    ACL = [
        {[{invoices, InvoiceID}]           , read },
        {[{invoices, InvoiceID}, payments] , read },
        {[{invoices, InvoiceID}, payments] , write},
        {[payment_resources              ] , write}
    ],
    Expiration = {lifetime, ?DEFAULT_INVOICE_ACCESS_TOKEN_LIFETIME},
    {Claims, ACL, Expiration};
resolve_token_spec({invoice_tpl, InvoiceTplID}) ->
    ACL = [
        {[party, {invoice_templates, InvoiceTplID}                           ], read },
        {[party, {invoice_templates, InvoiceTplID}, invoice_template_invoices], write}
    ],
    {#{}, ACL, unlimited};
resolve_token_spec({customer, CustomerID}) ->
    ACL = [
        {[{customers, CustomerID}], read},
        {[{customers, CustomerID}, bindings], read },
        {[{customers, CustomerID}, bindings], write},
        {[payment_resources], write}
    ],
    Expiration = {lifetime, ?DEFAULT_CUSTOMER_ACCESS_TOKEN_LIFETIME},
    {#{}, ACL, Expiration}.

-spec get_subject_id(uac:context()) -> binary().

get_subject_id({_Id, {SubjectID, _ACL}, _Claims}) ->
    SubjectID.

-spec get_claims(uac:context()) -> uac:claims().

get_claims({_Id, _Subject, Claims}) ->
    Claims.

-spec get_claim(binary(), uac:context()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}) ->
    maps:get(ClaimName, Claims).

-spec get_claim(binary(), uac:context(), term()) -> term().

get_claim(ClaimName, {_Id, _Subject, Claims}, Default) ->
    maps:get(ClaimName, Claims, Default).

%%

-spec get_operation_access(swag_server:operation_id(), swag_server:request_data()) ->
    [{uac_acl:scope(), uac_acl:permission()}].

get_operation_access('CreatePaymentResource'     , _) ->
    [{[payment_resources], write}].

-spec get_consumer(uac:claims()) ->
    consumer().
get_consumer(Claims) ->
    case maps:get(<<"cons">>, Claims, <<"merchant">>) of
        <<"merchant">> -> merchant;
        <<"client"  >> -> client;
        <<"provider">> -> provider
    end.

get_unique_id() ->
    <<ID:64>> = snowflake:new(),
    genlib_format:format_int_base(ID, 62).
