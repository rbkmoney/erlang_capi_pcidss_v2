-module(capi_handler_utils).

-include_lib("dmsl/include/dmsl_payment_processing_thrift.hrl").
-include_lib("dmsl/include/dmsl_domain_thrift.hrl").

-export([logic_error/2]).
-export([server_error/1]).

-export([service_call_with/3]).
-export([service_call/2]).

-export([get_auth_context/1]).

-export([issue_access_token/2]).
-export([merge_and_compact/2]).

-export([wrap_payment_session/2]).

-type processing_context() :: capi_handler:processing_context().
-type response()           :: capi_handler:response().

-spec logic_error(term(), io_lib:chars() | binary()) ->
    response().

logic_error(Code, Message) ->
    Data = #{<<"code">> => genlib:to_binary(Code), <<"message">> => genlib:to_binary(Message)},
    create_erorr_resp(400, Data).

create_erorr_resp(Code, Data) ->
    create_erorr_resp(Code, [], Data).
create_erorr_resp(Code, Headers, Data) ->
    {Code, Headers, Data}.

-spec server_error(integer()) ->
    {integer(), [], <<>>}.

server_error(Code) when Code >= 500 andalso Code < 600 ->
    {Code, [], <<>>}.

%%%

% Нужно быть аккуратным с флагами их порядок влияет на порядок аргументов при вызове функций!
% обычно параметры идут в порядке [user_info, party_id, party_creation],
% но это зависит от damsel протокола
-spec service_call_with(list(atom()), {atom(), atom(), list()}, processing_context()) ->
    woody:result().

service_call_with(Flags, Call, Context) ->
    % реверс тут чтобы в флагах писать порядок аналогично вызову функций
    service_call_with_(lists:reverse(Flags), Call, Context).

service_call_with_([user_info|T], {ServiceName, Function, Args}, Context) ->
    service_call_with_(T, {ServiceName, Function, [get_user_info(Context) | Args]}, Context);
service_call_with_([party_id|T], {ServiceName, Function, Args}, Context) ->
    service_call_with_(T, {ServiceName, Function, [get_party_id(Context) | Args]}, Context);
service_call_with_([party_creation|T], Call, Context) ->
    case service_call_with_(T, Call, Context) of
        {exception, #payproc_PartyNotFound{}} ->
            _ = lager:info("Attempting to create a missing party"),
            CreateCall = {party_management, 'Create', [get_party_params(Context)]},
            case service_call_with([user_info, party_id], CreateCall, Context) of
                {ok       , _                     } -> service_call_with_(T, Call, Context);
                {exception, #payproc_PartyExists{}} -> service_call_with_(T, Call, Context);
                Error                               -> Error
            end;
        Result ->
            Result
    end;
service_call_with_([], Call, Context) ->
    service_call(Call, Context).

-spec service_call({atom(), atom(), list()}, processing_context()) ->
    woody:result().

service_call({ServiceName, Function, Args}, #{woody_context := WoodyContext}) ->
    capi_woody_client:call_service(ServiceName, Function, Args, WoodyContext).

get_party_params(Context) ->
    #payproc_PartyParams{
        contact_info = #domain_PartyContactInfo{
            email = capi_auth:get_claim(<<"email">>, get_auth_context(Context))
        }
    }.

-spec get_auth_context(processing_context()) ->
    any().

get_auth_context(#{swagger_context := #{auth_context := AuthContext}}) ->
    AuthContext.

get_user_info(Context) ->
    #payproc_UserInfo{
        id = get_party_id(Context),
        type = {external_user, #payproc_ExternalUser{}}
    }.

-spec get_party_id(processing_context()) ->
    binary().

get_party_id(Context) ->
    capi_auth:get_subject_id(get_auth_context(Context)).

%% Utils

-spec issue_access_token(binary(), tuple()) ->
    map().

issue_access_token(PartyID, TokenSpec) ->
    #{<<"payload">> => capi_auth:issue_access_token(PartyID, TokenSpec)}.

-spec merge_and_compact(map(), map()) ->
    map().

merge_and_compact(M1, M2) ->
    genlib_map:compact(maps:merge(M1, M2)).

-spec wrap_payment_session(map(), binary()) ->
    binary().

wrap_payment_session(ClientInfo, PaymentSession) ->
    capi_utils:map_to_base64url(#{
        <<"clientInfo"    >> => ClientInfo,
        <<"paymentSession">> => PaymentSession
    }).
