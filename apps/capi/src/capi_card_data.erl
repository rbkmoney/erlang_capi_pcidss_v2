%%%
%%% Copyright 2019 RBKmoney
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%

-module(capi_card_data).

-include_lib("damsel/include/dmsl_cds_thrift.hrl").

-export([validate/1]).
-export([validate/2]).

-type cardholder_data() :: dmsl_cds_thrift:'CardData'().
-type session_data() :: dmsl_cds_thrift:'SessionData'().

-export_type([reason/0]).

%%

-type reason() :: unrecognized |{invalid, cardnumber | cvv | exp_date, check()}.

-spec validate(cardholder_data()) ->
    ok | {error, reason()}.

validate(CardData) ->
    validate(CardData, undefined, #{now => calendar:universal_time()}).

-spec validate(cardholder_data(), session_data() | undefined) ->
    ok| {error, reason()}.

validate(CardData, SessionData) ->
    validate(CardData, SessionData, #{now => calendar:universal_time()}).

-spec validate(cardholder_data(), session_data() | undefined, Env :: #{now := calendar:datetime()}) ->
    ok | {error, reason()}.

validate(CardData = #'CardData'{pan = CardNumber}, SessionData, Env) ->
    case detect_payment_system(CardNumber) of
        {ok, PaymentSystem} ->
            #{PaymentSystem := Ruleset} = get_payment_system_assertions(),
            validate_card_data(merge_data(CardData, SessionData), Ruleset, Env);
        {error, Reason} ->
            {error, Reason}
    end.

merge_data(CardData, undefined) ->
    convert_card_data(CardData);
merge_data(CardData, #'SessionData'{auth_data = AuthData}) ->
    CVV = get_cvv_from_session_data(AuthData),
    CardDataMap = convert_card_data(CardData),
    CardDataMap#{cvv => maybe_undefined(CVV)}.

get_cvv_from_session_data({card_security_code, AuthData}) ->
    AuthData#'CardSecurityCode'.value;
get_cvv_from_session_data(_) ->
    undefined.

detect_payment_system(CardNumber) ->
    detect_payment_system(byte_size(CardNumber), CardNumber).

detect_payment_system(Size, CardNumber) when Size > 0 ->
    <<Pre:Size/binary, _/binary>> = CardNumber,
    case get_inn_map() of
        #{Pre := PaymentSystem} ->
            {ok, PaymentSystem};
        #{} ->
            detect_payment_system(Size - 1, CardNumber)
    end;
detect_payment_system(0, _) ->
    {error, unrecognized}.

%%

validate_card_data(CardData, Assertions, Env) ->
    try run_assertions(CardData, Assertions, Env) catch
        Reason ->
            {error, Reason}
    end.

run_assertions(CardData, Assertions, Env) ->
    genlib_map:foreach(
        fun(K, Checks) ->
            V = maps:get(K, CardData, undefined),
            lists:foreach(
                fun(C) -> check_value(V, C, Env) orelse throw({invalid, K, C}) end,
                Checks
            )
        end,
        Assertions
    ).

check_value(undefined, _, _) ->
    true;
check_value(V, {length, Ls}, _) ->
    lists:any(fun(L) -> check_length(V, L) end, Ls);
check_value(V, luhn, _) ->
    check_luhn(V, 0);
check_value({M, Y}, expiration, #{now := {{Y0, M0, _DD}, _Time}}) ->
    M >= 1 andalso
        M =< 12 andalso
        {Y, M} >= {Y0, M0}.

check_length(V, {range, L, U}) ->
    L =< byte_size(V) andalso byte_size(V) =< U;
check_length(V, L) ->
    byte_size(V) =:= L.

check_luhn(<<CheckSum>>, Sum) ->
    case Sum * 9 rem 10 of
        M when M =:= CheckSum - $0 ->
            true;
        _M ->
            false
    end;
check_luhn(<<N, Rest/binary>>, Sum) when byte_size(Rest) rem 2 =:= 1 ->
    case (N - $0) * 2 of
        M when M >= 10 ->
            check_luhn(Rest, Sum + M div 10 + M rem 10);
        M ->
            check_luhn(Rest, Sum + M)
    end;
check_luhn(<<N, Rest/binary>>, Sum) ->
    check_luhn(Rest, Sum + N - $0).

% config

-type check() ::
    {length, [pos_integer() | {range, pos_integer(), pos_integer()}]} |
    luhn |
    expiration.

get_payment_system_assertions() ->
    #{

        visa => #{
            cardnumber => [{length, [13, 16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        mastercard => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        visaelectron => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        %% Maestro Global Rules
        %% https://www.mastercard.com/hr/merchants/_assets/Maestro_rules.pdf
        %%
        %% 6.2.1.3 Primary Account Number (PAN)
        %%
        %% The PAN must be no less than twelve (12) and no more than nineteen (19)
        %% digits in length. All digits of the PAN must be numeric. It is strongly
        %% recommended that Members issue Cards with a PAN of nineteen (19) digits.
        %%
        %% The IIN appears in the first six (6) digits of the PAN and must be assigned
        %% by the ISO Registration Authority, and must be unique.
        maestro => #{
            cardnumber => [{length, [{range, 12, 19}]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        nspkmir => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        amex => #{
            cardnumber => [{length, [15]}, luhn],
            cvv => [{length, [3, 4]}],
            exp_date => [expiration]
        },

        dinersclub => #{
            cardnumber => [{length, [{range, 14, 19}]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        discover => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        unionpay => #{
            cardnumber => [{length, [{range, 16, 19}]}],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        jcb => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        forbrugsforeningen => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        },

        dankort => #{
            cardnumber => [{length, [16]}, luhn],
            cvv => [{length, [3]}],
            exp_date => [expiration]
        }

    }.

get_inn_map() ->
    #{
        <<"4026">> => visaelectron,
        <<"417500">> => visaelectron,
        <<"4405">> => visaelectron,
        <<"4508">> => visaelectron,
        <<"4844">> => visaelectron,
        <<"4913">> => visaelectron,
        <<"4917">> => visaelectron,

        %% Maestro Global Rules
        %% https://www.mastercard.com/hr/merchants/_assets/Maestro_rules.pdf
        %%
        %% 6.2.1.3 Primary Account Number (PAN)
        %%
        %% The IIN appears in the first six (6) digits of the PAN and must be assigned
        %% by the ISO Registration Authority, and must be unique. This prefix will
        %% start with 50XXXX, 560000 through 589999, or 6XXXXX, but not 59XXXX.
        <<"50">> => maestro,
        <<"56">> => maestro,
        <<"57">> => maestro,
        <<"58">> => maestro,
        <<"6">> => maestro,

        <<"600">> => forbrugsforeningen,

        <<"5019">> => dankort,

        <<"4">> => visa,

        %% Mastercard Rules
        %% https://www.mastercard.us/content/dam/mccom/global/documents/mastercard-rules.pdf
        %%
        %% Any type of account (credit, debit, prepaid, commercial, etc.) identified
        %% as a Mastercard Account with a primary account number (PAN) that begins with
        %% a BIN in the range of 222100 to 272099 or 510000 to 559999.
        <<"51">> => mastercard,
        <<"52">> => mastercard,
        <<"53">> => mastercard,
        <<"54">> => mastercard,
        <<"55">> => mastercard,
        <<"2221">> => mastercard,
        <<"2222">> => mastercard,
        <<"2223">> => mastercard,
        <<"2224">> => mastercard,
        <<"2225">> => mastercard,
        <<"2226">> => mastercard,
        <<"2227">> => mastercard,
        <<"2228">> => mastercard,
        <<"2229">> => mastercard,
        <<"23">> => mastercard,
        <<"24">> => mastercard,
        <<"25">> => mastercard,
        <<"26">> => mastercard,
        <<"270">> => mastercard,
        <<"271">> => mastercard,
        <<"2720">> => mastercard,
        <<"500000">> => mastercard, %% needed for tinkoff test card

        <<"34">> => amex,
        <<"37">> => amex,

        <<"30">> => dinersclub,
        <<"36">> => dinersclub,
        <<"38">> => dinersclub,
        <<"39">> => dinersclub,

        <<"60">> => discover,
        <<"64">> => discover,
        <<"65">> => discover,
        <<"622">> => discover,

        <<"62">> => unionpay,
        <<"88">> => unionpay,

        <<"35">> => jcb,

        <<"2200">> => nspkmir,
        <<"2201">> => nspkmir,
        <<"2202">> => nspkmir,
        <<"2203">> => nspkmir,
        <<"2204">> => nspkmir
    }.


convert_card_data(CardData) ->
    #'CardData' {
        pan = PAN,
        cardholder_name = Cardholder,
        exp_date = #'ExpDate'{
            month = Month,
            year = Year
        }
    } = CardData,
    #{
        cardnumber => PAN,
        cardholder => Cardholder,
        exp_date => {Month, Year}
    }.

maybe_undefined(<<>>) ->
    undefined;
maybe_undefined(CVV) ->
    CVV.