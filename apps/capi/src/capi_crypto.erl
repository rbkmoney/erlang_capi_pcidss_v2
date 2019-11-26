-module(capi_crypto).

-type key() :: <<_:256>>.
-type iv()  :: binary().
-type tag() :: binary().
-type aad() :: binary().

%% Encrypted Data Format
-record(edf, {
    version :: binary(),
    tag     :: tag(),
    iv      :: iv(),
    aad     :: aad(),
    cipher  :: binary()
}).
-type edf() :: #edf{}.

-type options() :: #{secret_path := binary()}.

-export([get_child_spec/1]).
-export([init/1]).

-export([encrypt/1]).
-export([decrypt/2]).

-spec get_child_spec(options()) ->
    supervisor:child_spec() | no_return().

get_child_spec(Options) ->
    #{
        id => ?MODULE,
        start => {supervisor, start_link, [?MODULE, Options]},
        type => supervisor
    }.

-spec init(options()) ->
    {ok, {supervisor:sup_flags(), [supervisor:child_spec()]}}.

init(#{secret_path := Path}) ->
    Secret = read_secret_key(Path),
    ok = create_table(#{secret => Secret}),
    {ok, {#{}, []}}.

-spec read_secret_key(binary()) -> binary().

read_secret_key(SecretPath) ->
    {ok, Secret} = file:read_file(SecretPath),
    string:trim(Secret).

-spec encrypt(binary()) -> binary().
encrypt(Plain) ->
    IV = iv(),
    AAD = aad(),
    Version = <<"edf_v1">>,
    Key = lookup_value(secret),
    try
        {Cipher, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {AAD, Plain}),
        marshall_edf(#edf{version = Version, iv = IV, aad = AAD, cipher = Cipher, tag = Tag})
    catch Class:Reason ->
        _ = logger:error("encryption failed with ~p ~p", [Class, Reason]),
        throw(encryption_failed)
    end.

-spec decrypt(key(), binary()) -> binary().
decrypt(Key, MarshalledEDF) ->
    try
        #edf{iv = IV, aad = AAD, cipher = Cipher, tag = Tag} = unmarshall_edf(MarshalledEDF),
        crypto:block_decrypt(aes_gcm, Key, IV, {AAD, Cipher, Tag})
    of
        error ->
            throw(decryption_failed);
        Plain ->
            Plain
    catch Type:Error ->
        _ = logger:error("decryption failed with ~p ~p", [Type, Error]),
        throw(decryption_failed)
    end.

%%% Internal functions

-spec iv() -> iv().
iv() ->
    crypto:strong_rand_bytes(16).

-spec aad() -> aad().
aad() ->
    crypto:strong_rand_bytes(4).

-spec marshall_edf(edf()) -> binary().
marshall_edf(#edf{version = Ver, tag = Tag, iv = IV, aad = AAD, cipher = Cipher})
    when
        bit_size(Tag) =:= 128,
        bit_size(IV) =:= 128,
        bit_size(AAD) =:= 32
    ->
        <<Ver:6/binary, Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>.

-spec unmarshall_edf(binary()) -> edf().
unmarshall_edf(<<"edf_v1", Tag:16/binary, IV:16/binary, AAD:4/binary, Cipher/binary>>) ->
    #edf{version = <<"edf_v1">>, tag = Tag, iv = IV, aad = AAD, cipher = Cipher}.

%%

-define(TABLE, ?MODULE).

create_table(Values) ->
    _ = ets:new(?TABLE, [set, public, named_table, {read_concurrency, true}]),
    insert_values(Values),
    ok.

insert_values(Values) ->
    true = ets:insert(?TABLE, maps:to_list(Values)),
    ok.

lookup_value(Key) ->
    case ets:lookup(?TABLE, Key) of
        [{Key, Value}] ->
            Value;
        [] ->
            undefined
    end.
