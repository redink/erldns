%% Copyright (c) 2012-2018, DNSimple Corporation
%%
%% Permission to use, copy, modify, and/or distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @doc Process for parsing zone data from JSON to Erlang representations.
-module(erldns_zone_parser).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([zone_to_erlang/1]).

%% @doc Takes a JSON zone and turns it into the tuple {Name, Sha, Records}.
%%
%% The default timeout for parsing is currently 30 seconds.
-spec zone_to_erlang(binary()) -> {binary(), binary(), [dns:rr()], [erldns:keyset()]}.
zone_to_erlang(Zone) ->
  json_to_erlang(Zone, []).

% Internal API
json_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}], Parsers) ->
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, ""}, {<<"records">>, JsonRecords}, {<<"keys">>, []}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers) ->
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, ""}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}], Parsers) ->
  json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}, {<<"keys">>, []}], Parsers);

json_to_erlang([{<<"name">>, Name}, {<<"sha">>, Sha}, {<<"records">>, JsonRecords}, {<<"keys">>, JsonKeys}], Parsers) ->
  Records = lists:map(
              fun(JsonRecord) ->
                  Data = json_record_to_list(JsonRecord),

                  % Filter by context
                  case apply_context_options(Data) of
                    pass ->
                      case json_record_to_erlang(Data) of
                        {} ->
                          case try_custom_parsers(Data, Parsers) of
                            {} ->
                                lager:warning("Unsupported record (data: ~p)", [Data]),
                                {};
                            ParsedRecord -> ParsedRecord
                          end;
                        ParsedRecord -> ParsedRecord
                      end;
                    _ ->
                      {}
                  end
              end, JsonRecords),
  FilteredRecords = lists:filter(record_filter(), Records),
  DistinctRecords = lists:usort(FilteredRecords),
  {Name, Sha, DistinctRecords, parse_json_keys(JsonKeys)}.

parse_json_keys(JsonKeys) -> parse_json_keys(JsonKeys, []).

parse_json_keys([], Keys) -> Keys;
parse_json_keys([[{<<"ksk">>, KskBin}, {<<"ksk_keytag">>, KskKeytag}, {<<"ksk_alg">>, KskAlg}, {<<"zsk">>, ZskBin}, {<<"zsk_keytag">>, ZskKeytag}, {<<"zsk_alg">>, ZskAlg}, {<<"inception">>, Inception}, {<<"until">>, ValidUntil}]|Rest], Keys) ->
  KeySet = #keyset{
              key_signing_key = to_crypto_key(KskBin),
              key_signing_key_tag = KskKeytag,
              key_signing_alg = KskAlg,
              zone_signing_key = to_crypto_key(ZskBin),
              zone_signing_key_tag = ZskKeytag,
              zone_signing_alg = ZskAlg,
              inception = iso8601:parse(Inception),
              valid_until = iso8601:parse(ValidUntil)
             },
  parse_json_keys(Rest, [KeySet | Keys]).

to_crypto_key(RsaKeyBin) ->
  % Where E is the public exponent, N is public modulus and D is the private exponent
  [_,_,M,E,N|_] = tuple_to_list(public_key:pem_entry_decode(lists:last(public_key:pem_decode(RsaKeyBin)))),
  [E,M,N].

record_filter() ->
  fun(R) ->
      case R of
        {} -> false;
        _ -> true
      end
  end.

-spec apply_context_list_check(sets:set(), sets:set()) -> [fail] | [pass].
apply_context_list_check(ContextAllowSet, ContextSet) ->
  case sets:size(sets:intersection(ContextAllowSet, ContextSet)) of
    0 -> [fail];
    _ -> [pass]
  end.

-spec apply_context_match_empty_check(boolean(), [any()]) -> [fail] | [pass].
apply_context_match_empty_check(true, []) -> [pass];
apply_context_match_empty_check(_, _) -> [fail].

%% Determine if a record should be used in this name server's context.
%%
%% If the context is undefined then the record will always be used.
%%
%% If the context is a list and has at least one condition that passes
%% then it will be included in the zone
-spec apply_context_options([any()]) -> pass | fail.
apply_context_options([_, _, _, _, undefined]) -> pass;
apply_context_options([_, _, _, _, Context]) ->
  case application:get_env(erldns, context_options) of
    {ok, ContextOptions} ->
      ContextSet = sets:from_list(Context),
      Result = lists:append([
                             apply_context_match_empty_check(erldns_config:keyget(match_empty, ContextOptions), Context),
                             apply_context_list_check(sets:from_list(erldns_config:keyget(allow, ContextOptions)), ContextSet)
                            ]),
      case lists:any(fun(I) -> I =:= pass end, Result) of
        true -> pass;
        _ -> fail
      end;
    _ ->
      pass
  end.

json_record_to_list(JsonRecord) ->
  [
   erldns_config:keyget(<<"name">>, JsonRecord),
   erldns_config:keyget(<<"type">>, JsonRecord),
   erldns_config:keyget(<<"ttl">>, JsonRecord),
   erldns_config:keyget(<<"data">>, JsonRecord),
   erldns_config:keyget(<<"context">>, JsonRecord)
  ].

try_custom_parsers([_Name, _Type, _Ttl, _Rdata, _Context], []) ->
  {};
try_custom_parsers(Data, [Parser|Rest]) ->
  case Parser:json_record_to_erlang(Data) of
    {} -> try_custom_parsers(Data, Rest);
    Record -> Record
  end.

% Internal converters
json_record_to_erlang([Name, Type, _Ttl, null, _]) ->
  lager:error("Record has null data (name: ~p, type: ~p)", [Name, Type]),
  {};

json_record_to_erlang([Name, <<"SOA">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_SOA,
     data = #dns_rrdata_soa{
               mname = erldns_config:keyget(<<"mname">>, Data),
               rname = erldns_config:keyget(<<"rname">>, Data),
               serial = erldns_config:keyget(<<"serial">>, Data),
               refresh = erldns_config:keyget(<<"refresh">>, Data),
               retry = erldns_config:keyget(<<"retry">>, Data),
               expire = erldns_config:keyget(<<"expire">>, Data),
               minimum = erldns_config:keyget(<<"minimum">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"NS">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_NS,
     data = #dns_rrdata_ns{
               dname = erldns_config:keyget(<<"dname">>, Data)
              },
     ttl = Ttl};

json_record_to_erlang([Name, <<"A">>, Ttl, Data, _Context]) ->
  Ip = erldns_config:keyget(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_A, data = #dns_rrdata_a{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse A record address (ip: ~p, reason: ~p)", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"AAAA">>, Ttl, Data, _Context]) ->
  Ip = erldns_config:keyget(<<"ip">>, Data),
  case inet_parse:address(binary_to_list(Ip)) of
    {ok, Address} ->
      #dns_rr{name = Name, type = ?DNS_TYPE_AAAA, data = #dns_rrdata_aaaa{ip = Address}, ttl = Ttl};
    {error, Reason} ->
      lager:error("Failed to parse AAAA record address (ip: ~p, reason: ~p)", [Ip, Reason]),
      {}
  end;

json_record_to_erlang([Name, <<"CNAME">>, Ttl, Data, _Context]) ->
  #dns_rr{
     name = Name,
     type = ?DNS_TYPE_CNAME,
     data = #dns_rrdata_cname{dname = erldns_config:keyget(<<"dname">>, Data)},
     ttl = Ttl};


json_record_to_erlang(_Data) ->
  {}.
