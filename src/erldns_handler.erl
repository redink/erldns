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

%% @doc The module that handles the resolution of a single DNS question.
%%
%% The meat of the resolution occurs in erldns_resolver:resolve/3
-module(erldns_handler).

-include_lib("dns/include/dns.hrl").
-include("erldns.hrl").

-export([handle/2]).


%% If the message has trailing garbage just throw the garbage away and continue
%% trying to process the message.
handle({trailing_garbage, Message, _}, Context) ->
  handle(Message, Context);
%% Handle the message, checking to see if it is throttled.
handle(Message, {_, Host}) when is_record(Message, dns_message) ->
  handle_message(Message, Host);
%% The message was bad so just return it.
%% TODO: consider just throwing away the message
handle(BadMessage, {_, Host}) ->
  BadMessage.

%% Handle the message by hitting the packet cache and either
%% using the cached packet or continuing with the lookup process.
%%
%% If the cache is missed, then the SOA (Start of Authority) is discovered here.
handle_message(Message, Host) ->
  case erldns_packet_cache:get({Message#dns_message.questions, Message#dns_message.additional}, Host) of
    {ok, CachedResponse} ->
      CachedResponse#dns_message{id=Message#dns_message.id};
    {error, Reason} ->
      handle_packet_cache_miss(Message, get_authority(Message), Host) % SOA lookup
  end.

%% If the packet is not in the cache and we are not authoritative (because there
%% is no SOA record for this zone), then answer immediately setting the AA flag to false.
%% If erldns is configured to use root hints then those will be added to the response.
-spec(handle_packet_cache_miss(Message :: dns:message(), AuthorityRecords :: dns:authority(), Host :: dns:ip()) -> dns:message()).
handle_packet_cache_miss(Message, [], _Host) ->
  Message#dns_message{aa = false, rc = ?DNS_RCODE_REFUSED};

%% The packet is not in the cache yet we are authoritative, so try to resolve
%% the request. This is the point the request moves on to the erldns_resolver
%% module.
handle_packet_cache_miss(Message, AuthorityRecords, Host) ->
  safe_handle_packet_cache_miss(Message#dns_message{ra = false}, AuthorityRecords, Host).

-spec(safe_handle_packet_cache_miss(Message :: dns:message(), AuthorityRecords :: dns:authority(), Host :: dns:ip()) -> dns:message()).
safe_handle_packet_cache_miss(Message, AuthorityRecords, Host) ->
  try erldns_resolver:resolve(Message, AuthorityRecords, Host) of
    Response ->
      maybe_cache_packet(Response, Response#dns_message.aa)
  catch
    _Exception:_Reason ->
      Message#dns_message{aa = false, rc = ?DNS_RCODE_SERVFAIL}
  end.

%% We are authoritative so cache the packet and return the message.
maybe_cache_packet(Message, true) ->
  erldns_packet_cache:put({Message#dns_message.questions, Message#dns_message.additional}, Message),
  Message;

%% We are not authoritative so just return the message.
maybe_cache_packet(Message, false) ->
  Message.

%% Get the SOA authority for the current query.
get_authority(MessageOrName) ->
  case erldns_zone_cache:get_authority(MessageOrName) of
    {ok, Authority} -> Authority;
    {error, _} -> []
  end.
