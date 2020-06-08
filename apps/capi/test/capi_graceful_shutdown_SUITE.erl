-module(capi_graceful_shutdown_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("stdlib/include/assert.hrl").

-include_lib("damsel/include/dmsl_domain_config_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_processing_errors_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_provider_thrift.hrl").
-include_lib("damsel/include/dmsl_payment_tool_token_thrift.hrl").
-include_lib("binbase_proto/include/binbase_binbase_thrift.hrl").
-include_lib("cds_proto/include/cds_proto_storage_thrift.hrl").
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
    shutdown_test/1,
    request_interrupt_test/1
]).

-define(NUMBER_OF_WORKERS, 10).

-define(CAPI_PORT                   , 8080).
-define(CAPI_HOST_NAME              , "localhost").
-define(CAPI_URL                    , ?CAPI_HOST_NAME ++ ":" ++ integer_to_list(?CAPI_PORT)).

-define(IDEMPOTENT_KEY, <<"capi/CreatePaymentResource/TEST/ext_id">>).

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
        {group, all_tests}
    ].

-spec groups() ->
    [{group_name(), list(), [test_case_name()]}].
groups() ->
    [
        {all_tests, [],
            [
                shutdown_test,
                request_interrupt_test
            ]
        }
    ].

%%
%% starting/stopping
%%
-spec init_per_suite(config()) ->
    config().
init_per_suite(Config) ->
    _ = dbg:tracer(),
    _ = dbg:p(all, c),
    _ = dbg:tpl({'capi_payment_resources_tests_SUITE', 'p', '_'}, x),
    _ = dbg:tpl({'capi_handler_tokens', 'p', '_'}, x),
   capi_ct_helper:init_suite(?MODULE, Config).

-spec end_per_suite(config()) ->
    _.
end_per_suite(C) ->
    _ = capi_ct_helper:stop_mocked_service_sup(?config(suite_test_sup, C)),
    [application:stop(App) || App <- proplists:get_value(apps, C)],
    ok.

-spec init_per_group(group_name(), config()) ->
    config().

init_per_group(_, Config) ->
    Token = capi_ct_helper:issue_token([{[payment_resources], write}], unlimited),
    [{context, capi_ct_helper:get_context(Token)} | Config].

-spec end_per_group(group_name(), config()) ->
    _.
end_per_group(_Group, C) ->
    proplists:delete(context, C),
    ok.

-spec init_per_testcase(test_case_name(), config()) ->
    config().
init_per_testcase(_Name, C) ->
    [{test_sup, capi_ct_helper:start_mocked_service_sup(?MODULE)} | C].

-spec end_per_testcase(test_case_name(), config()) ->
    config().
end_per_testcase(_Name, C) ->
    _ = application:start(capi_pcidss),
    capi_ct_helper:stop_mocked_service_sup(?config(test_sup, C)),
    ok.

%%% Tests

-spec shutdown_test(config()) -> _.

shutdown_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
                ok = timer:sleep(2000),
                {ok, #cds_PutCardResult{
                    bank_card = #cds_BankCard{
                        token = ?STRING,
                        bin = <<"411111">>,
                        last_digits = Mask
                    }
                }}
            end},
        {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    Token = get_token(),
    ok = spawn_workers(Token, self(), ?NUMBER_OF_WORKERS),
    ok = timer:sleep(1000),
    ok = application:stop(capi_pcidss),
    ok = receive_loop(fun(Result) -> {ok, _} = Result end, ?NUMBER_OF_WORKERS, timer:seconds(20)),
    ok = spawn_workers(Token, self(), ?NUMBER_OF_WORKERS),
    ok = receive_loop(fun(Result) -> {error, econnrefused} = Result end, ?NUMBER_OF_WORKERS, timer:seconds(20)).

-spec request_interrupt_test(config()) -> _.

request_interrupt_test(Config) ->
    capi_ct_helper:mock_services([
        {cds_storage, fun
            ('PutSession', _) -> {ok, ok};
            ('PutCard', [
                #cds_PutCardData{pan = <<"411111", _:6/binary, Mask:4/binary>>}
            ]) ->
                ok = timer:sleep(20000),
                {ok, #cds_PutCardResult{
                    bank_card = #cds_BankCard{
                        token = ?STRING,
                        bin = <<"411111">>,
                        last_digits = Mask
                    }
                }}
            end},
        {bender, fun('GenerateID', _) -> {ok, capi_ct_helper_bender:get_result(<<"bender_key">>)} end},
        {binbase, fun('Lookup', _) -> {ok, ?BINBASE_LOOKUP_RESULT(<<"VISA">>)} end}
    ], Config),
    Token = get_token(),
    ok = spawn_workers(Token, self(), ?NUMBER_OF_WORKERS),
    ok = timer:sleep(1000),
    ok = application:stop(capi_pcidss),
    ok = receive_loop(fun({error, closed}) -> ok end, ?NUMBER_OF_WORKERS, timer:seconds(20)),
    ok = spawn_workers(Token, self(), ?NUMBER_OF_WORKERS),
    ok = receive_loop(fun(Result) -> {error, econnrefused} = Result end, ?NUMBER_OF_WORKERS, timer:seconds(20)).

%%%

receive_loop(_, N, _Timeout) when N =< 0 ->
    ok;
receive_loop(MatchFun, N, Timeout) ->
    receive
        {result, Result} ->
            MatchFun(Result)
    after Timeout ->
        error(timeout)
    end,
    receive_loop(MatchFun, N - 1, Timeout).

spawn_workers(_, _, N) when N =< 0 ->
    ok;
spawn_workers(Token, ParentPID, N) ->
    erlang:spawn_link(fun() -> worker(Token, ParentPID) end),
    spawn_workers(Token, ParentPID, N - 1).

worker(Token, ParentPID) ->
    Context = get_context(Token),
    ClientInfo = #{<<"fingerprint">> => <<"test fingerprint">>},
    Result = capi_client_tokens:create_payment_resource(Context, #{
        <<"paymentTool">> => #{
            <<"paymentToolType">> => <<"CardData">>,
            <<"cardNumber">> => <<"4111111111111111">>,
            <<"cardHolder">> => <<"Alexander Weinerschnitzel">>,
            <<"expDate">> => <<"03/20">>,
            <<"cvv">> => <<"232">>
        },
        <<"clientInfo">> => ClientInfo
    }),
    ParentPID ! {result, Result}.

get_context(Token) ->
    Deadline = build_deadline(genlib_time:now()),
    capi_ct_helper:get_context(Token, #{}, Deadline).

get_token() ->
    capi_ct_helper:issue_token([{[payment_resources], write}], unlimited).

build_deadline(CurrentSeconds) ->
    genlib_rfc3339:format_relaxed(genlib_time:add_hours(CurrentSeconds, 1), second).
