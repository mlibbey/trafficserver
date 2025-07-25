/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#include <bitset>
#include <algorithm>
#include <array>
#include <string_view>

#include "tscore/ink_platform.h"

#include "proxy/http/HttpTransact.h"
#include "proxy/http/HttpTransactHeaders.h"
#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/HdrUtils.h"
#include "proxy/hdrs/HttpCompat.h"
#include "proxy/hdrs/MIME.h"
#include "proxy/http/HttpSM.h"
#include "proxy/PoolableSession.h"
#include "proxy/hdrs/HTTP.h"

#include "iocore/utils/Machine.h"

using namespace std::literals;

namespace
{
DbgCtl dbg_ctl_http_trans{"http_trans"};
DbgCtl dbg_ctl_http_transact_headers{"http_transact_headers"};
DbgCtl dbg_ctl_anon{"anon"};

} // end anonymous namespace

bool
HttpTransactHeaders::is_method_cacheable(const OverridableHttpConfigParams *http_config_param, const int method)
{
  return (method == HTTP_WKSIDX_GET || method == HTTP_WKSIDX_HEAD ||
          (http_config_param->cache_post_method == 1 && method == HTTP_WKSIDX_POST));
}

bool
HttpTransactHeaders::is_method_cache_lookupable(int method)
{
  // responses to GET, HEAD, and POST are cacheable
  // URL's requested in DELETE and PUT are looked up to remove cached copies
  return (method == HTTP_WKSIDX_GET || method == HTTP_WKSIDX_HEAD || method == HTTP_WKSIDX_POST || method == HTTP_WKSIDX_DELETE ||
          method == HTTP_WKSIDX_PUT || method == HTTP_WKSIDX_PURGE || method == HTTP_WKSIDX_PUSH);
}

bool
HttpTransactHeaders::is_this_a_hop_by_hop_header(const char *field_name)
{
  if (!hdrtoken_is_wks(field_name)) {
    return (false);
  }
  if ((hdrtoken_wks_to_flags(field_name) & HdrTokenInfoFlags::HOPBYHOP) != HdrTokenInfoFlags::NONE &&
      (field_name != MIME_FIELD_KEEP_ALIVE.c_str())) {
    return (true);
  } else {
    return (false);
  }
}

bool
HttpTransactHeaders::is_this_method_supported(int the_scheme, int the_method)
{
  if (the_method == HTTP_WKSIDX_CONNECT) {
    return true;
  } else if (the_scheme == URL_WKSIDX_HTTP || the_scheme == URL_WKSIDX_HTTPS) {
    return is_this_http_method_supported(the_method);
  } else if ((the_scheme == URL_WKSIDX_WS || the_scheme == URL_WKSIDX_WSS) && the_method == HTTP_WKSIDX_GET) {
    return true;
  } else {
    return false;
  }
}

bool
HttpTransactHeaders::is_method_safe(int method)
{
  // See RFC 7231, section 4.2.1.
  return (method == HTTP_WKSIDX_GET || method == HTTP_WKSIDX_OPTIONS || method == HTTP_WKSIDX_HEAD || method == HTTP_WKSIDX_TRACE);
}

bool
HttpTransactHeaders::is_status_an_error_response(HTTPStatus response_code)
{
  auto const comparable_response_code = static_cast<unsigned int>(response_code);
  return (comparable_response_code >= 400) && (comparable_response_code <= 599);
}

bool
HttpTransactHeaders::is_method_idempotent(int method)
{
  return (method == HTTP_WKSIDX_CONNECT || method == HTTP_WKSIDX_DELETE || method == HTTP_WKSIDX_GET ||
          method == HTTP_WKSIDX_HEAD || method == HTTP_WKSIDX_PUT || method == HTTP_WKSIDX_OPTIONS || method == HTTP_WKSIDX_TRACE);
}

void
HttpTransactHeaders::insert_supported_methods_in_response(HTTPHdr *response, int scheme)
{
  int         method_output_lengths[32];
  const char *methods[] = {
    HTTP_METHOD_CONNECT.c_str(), HTTP_METHOD_DELETE.c_str(), HTTP_METHOD_GET.c_str(),   HTTP_METHOD_HEAD.c_str(),
    HTTP_METHOD_OPTIONS.c_str(), HTTP_METHOD_POST.c_str(),   HTTP_METHOD_PURGE.c_str(), HTTP_METHOD_PUT.c_str(),
    HTTP_METHOD_PUSH.c_str(),    HTTP_METHOD_TRACE.c_str(),
  };
  char  inline_buffer[64];
  char *alloced_buffer, *value_buffer;

  int nmethods = sizeof(methods) / sizeof(methods[0]);
  ink_assert(nmethods <= 32);

  char      *p;
  int        i, is_supported;
  size_t     bytes                 = 0;
  int        num_methods_supported = 0;
  MIMEField *field;

  // step 1: determine supported methods, count bytes & allocate
  for (i = 0; i < nmethods; i++) {
    const char *method_wks = methods[i];
    ink_assert(hdrtoken_is_wks(method_wks));

    is_supported = is_this_method_supported(scheme, hdrtoken_wks_to_index(method_wks));

    if (is_supported) {
      ++num_methods_supported;
      method_output_lengths[i]  = hdrtoken_wks_to_length(method_wks);
      bytes                    += method_output_lengths[i];
      if (num_methods_supported > 1) {
        bytes += 2; // +2 if need leading ", "
      }
    } else {
      method_output_lengths[i] = 0;
    }
  }

  // step 2: create Allow field if not present
  field = response->field_find(static_cast<std::string_view>(MIME_FIELD_ALLOW));
  if (!field) {
    field = response->field_create(static_cast<std::string_view>(MIME_FIELD_ALLOW));
    response->field_attach(field);
  }
  // step 3: get a big enough buffer
  if (bytes <= sizeof(inline_buffer)) {
    alloced_buffer = nullptr;
    value_buffer   = inline_buffer;
  } else {
    alloced_buffer = static_cast<char *>(ats_malloc(bytes));
    value_buffer   = alloced_buffer;
  }

  // step 4: build the value
  p = value_buffer;
  for (i = 0; i < nmethods; i++) {
    if (method_output_lengths[i]) {
      memcpy(p, methods[i], method_output_lengths[i]);
      p += method_output_lengths[i];
      if (num_methods_supported > 1) {
        *p++ = ',';
        *p++ = ' ';
      }
      --num_methods_supported;
    }
  }

  // FIXME: do we really want to append to old list, or replace old list?

  // step 5: attach new allow list to end of previous list
  field->value_append(response->m_heap, response->m_mime, value_buffer, bytes);

  // step 6: free up temp storage
  ats_free(alloced_buffer);
}

void
HttpTransactHeaders::build_base_response(HTTPHdr *outgoing_response, HTTPStatus status, const char *reason_phrase,
                                         int reason_phrase_len, ink_time_t date)
{
  if (!outgoing_response->valid()) {
    outgoing_response->create(HTTPType::RESPONSE);
  }

  ink_assert(outgoing_response->type_get() == HTTPType::RESPONSE);

  outgoing_response->version_set(HTTPVersion(1, 1));
  outgoing_response->status_set(status);
  outgoing_response->reason_set(std::string_view{reason_phrase, static_cast<std::string_view::size_type>(reason_phrase_len)});
  outgoing_response->set_date(date);
}

////////////////////////////////////////////////////////////////////////
// Copy all non hop-by-hop header fields from src_hdr to new_hdr.
// If header Date: is not present or invalid in src_hdr,
// then the given date will be used.
void
HttpTransactHeaders::copy_header_fields(HTTPHdr *src_hdr, HTTPHdr *new_hdr, bool retain_proxy_auth_hdrs, ink_time_t date)
{
  ink_assert(src_hdr->valid());
  ink_assert(!new_hdr->valid());

  bool date_hdr = false;

  // Start with an exact duplicate
  new_hdr->copy(src_hdr);

  // Nuke hop-by-hop headers
  //
  //    The hop-by-hop header fields are laid out by the spec
  //    with two adjustments
  //      1) we treat TE as hop-by-hop because spec implies
  //         that it is by declaring anyone who sends a TE must
  //         include TE in the connection header.  This in
  //         my opinion error prone and if the client doesn't follow the spec
  //         we'll have problems with the TE being forwarded to the server
  //         and us caching the transfer encoded documents and then
  //         serving it to a client that can not handle it. The exception
  //         to this is that we will allow "TE: trailers" to be forwarded
  //         because that is required for gRPC traffic.
  //      2) Transfer encoding is copied.  If the transfer encoding
  //         is changed for example by dechunking, the transfer encoding
  //         should be modified when the decision is made to dechunk it

  for (auto &field : *new_hdr) {
    if (field.m_wks_idx == -1) {
      continue;
    }

    HdrTokenInfoFlags field_flags = hdrtoken_index_to_flags(field.m_wks_idx);

    if ((field_flags & HdrTokenInfoFlags::HOPBYHOP) != HdrTokenInfoFlags::NONE) {
      std::string_view name(field.name_get());
      std::string_view value(field.value_get());
      bool const       is_te_trailers = name == MIME_FIELD_TE.c_str() && value == "trailers";
      if (is_te_trailers) {
        // te: trailers is used by gRPC, do not delete it.
        continue;
      }

      // Delete header if not in special proxy_auth retention mode
      if (retain_proxy_auth_hdrs && (field_flags & HdrTokenInfoFlags::PROXYAUTH) != HdrTokenInfoFlags::NONE) {
        continue;
      }
      new_hdr->field_delete(&field);
    } else if (field.m_wks_idx == MIME_WKSIDX_DATE) {
      date_hdr = true;
    }
  }

  // Set date hdr if not already set and valid value passed in
  if ((date_hdr == false) && (date > 0)) {
    new_hdr->set_date(date);
  }
}

////////////////////////////////////////////////////////////////////////
// Just convert the outgoing request to the appropriate version
void
HttpTransactHeaders::convert_request(HTTPVersion outgoing_ver, HTTPHdr *outgoing_request)
{
  if (outgoing_ver == HTTPVersion(1, 1)) {
    convert_to_1_1_request_header(outgoing_request);
  } else if (outgoing_ver == HTTPVersion(1, 0)) {
    convert_to_1_0_request_header(outgoing_request);
  } else {
    Dbg(dbg_ctl_http_trans, "[HttpTransactHeaders::convert_request]"
                            "Unsupported Version - passing through");
  }
}

////////////////////////////////////////////////////////////////////////
// Just convert the outgoing response to the appropriate version
void
HttpTransactHeaders::convert_response(HTTPVersion outgoing_ver, HTTPHdr *outgoing_response, char const *reason_phrase)
{
  if (outgoing_ver == HTTPVersion(1, 1)) {
    convert_to_1_1_response_header(outgoing_response, reason_phrase);
  } else if (outgoing_ver == HTTPVersion(1, 0)) {
    convert_to_1_0_response_header(outgoing_response, reason_phrase);
  } else {
    Dbg(dbg_ctl_http_trans, "[HttpTransactHeaders::convert_response]"
                            "Unsupported Version - passing through");
  }
}

////////////////////////////////////////////////////////////////////////
// Take an existing outgoing request header and make it HTTP/1.0
void
HttpTransactHeaders::convert_to_1_0_request_header(HTTPHdr *outgoing_request)
{
  // These are required
  ink_assert(outgoing_request->url_get()->valid());

  // Set HTTP version to 1.0
  outgoing_request->version_set(HTTPVersion(1, 0));

  // FIXME (P2): Need to change cache directives into pragma, cleanly
  //             Now, any Cache-Control hdr becomes Pragma: no-cache

  if (outgoing_request->presence(MIME_PRESENCE_CACHE_CONTROL) && !outgoing_request->is_pragma_no_cache_set()) {
    outgoing_request->value_append(static_cast<std::string_view>(MIME_FIELD_PRAGMA), "no-cache"sv, true);
  }
  // We do not currently support chunked transfer encoding,
  // so specify that response should use identity transfer coding.
  // outgoing_request->value_insert(MIME_FIELD_TE, "identity;q=1.0");
  // outgoing_request->value_insert(MIME_FIELD_TE, "chunked;q=0.0");
}

////////////////////////////////////////////////////////////////////////
// Take an existing outgoing request header and make it HTTP/1.1
void
HttpTransactHeaders::convert_to_1_1_request_header(HTTPHdr *outgoing_request)
{
  // These are required
  ink_assert(outgoing_request->url_get()->valid());
  ink_assert(outgoing_request->version_get() == HTTPVersion(1, 1));

  if (outgoing_request->get_cooked_pragma_no_cache() && !(outgoing_request->get_cooked_cc_mask() & MIME_COOKED_MASK_CC_NO_CACHE)) {
    outgoing_request->value_append(static_cast<std::string_view>(MIME_FIELD_CACHE_CONTROL), "no-cache"sv, true);
  }
  // We do not currently support chunked transfer encoding,
  // so specify that response should use identity transfer coding.
  // outgoing_request->value_insert(MIME_FIELD_TE, "identity;q=1.0");
  // outgoing_request->value_insert(MIME_FIELD_TE, "chunked;q=0.0");
}

////////////////////////////////////////////////////////////////////////
// Take an existing outgoing response header and make it HTTP/1.0
void
HttpTransactHeaders::convert_to_1_0_response_header(HTTPHdr *outgoing_response, char const *reason_phrase)
{
  //     // These are required
  //     ink_assert(outgoing_response->status_get());
  //     ink_assert(outgoing_response->reason_get());

  // Set HTTP version to 1.0
  outgoing_response->version_set(HTTPVersion(1, 0));

  // Set reason phrase if passed in.
  if (reason_phrase != nullptr) {
    Dbg(dbg_ctl_http_transact_headers, "Setting HTTP/1.0 reason phrase to '%s'", reason_phrase);
    outgoing_response->reason_set(std::string_view{reason_phrase});
  }

  // Keep-Alive?

  // Cache-Control?
}

////////////////////////////////////////////////////////////////////////
// Take an existing outgoing response header and make it HTTP/1.1
void
HttpTransactHeaders::convert_to_1_1_response_header(HTTPHdr *outgoing_response, char const *reason_phrase)
{
  // These are required
  ink_assert(outgoing_response->status_get() != HTTPStatus::NONE);

  // Set HTTP version to 1.1
  outgoing_response->version_set(HTTPVersion(1, 1));

  // Set reason phrase if passed in.
  if (reason_phrase != nullptr) {
    Dbg(dbg_ctl_http_transact_headers, "Setting HTTP/1.1 reason phrase to '%s'", reason_phrase);
    outgoing_response->reason_set(std::string_view{reason_phrase});
  }
}

bool
HttpTransactHeaders::does_server_allow_response_to_be_stored(HTTPHdr *resp, bool ignore_no_store_and_no_cache_directives)
{
  uint32_t cc_mask = MIME_COOKED_MASK_CC_PRIVATE | (ignore_no_store_and_no_cache_directives ? 0 : MIME_COOKED_MASK_CC_NO_STORE);

  // According to https://www.rfc-editor.org/rfc/rfc7234#section-5.4
  // ... When the Cache-Control header field is also present and
  // understood in a request, Pragma is ignored.
  if (!ignore_no_store_and_no_cache_directives && resp->get_cooked_cc_mask() == 0 && resp->get_cooked_pragma_no_cache()) {
    return false;
  } else if (resp->get_cooked_cc_mask() & cc_mask) {
    return false;
  } else {
    return true;
  }
}

bool
HttpTransactHeaders::downgrade_request(bool *origin_server_keep_alive, HTTPHdr *outgoing_request)
{
  // HTTPVersion ver;
  /* First try turning keep_alive off */
  if (*origin_server_keep_alive) {
    *origin_server_keep_alive = false;
  }

  if (outgoing_request->version_get() == HTTPVersion(1, 1)) {
    convert_to_1_0_request_header(outgoing_request);
  } else {
    return false;
  }

  return true;
}

void
HttpTransactHeaders::generate_and_set_squid_codes(HTTPHdr *header, char *via_string, HttpTransact::SquidLogInfo *squid_codes)
{
  SquidLogCode       log_code      = SquidLogCode::EMPTY;
  SquidHierarchyCode hier_code     = SquidHierarchyCode::EMPTY;
  SquidHitMissCode   hit_miss_code = SQUID_HIT_RESERVED;

  /////////////////////////////
  // First the Hit-Miss Code //
  /////////////////////////////
  if ((via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_HIT_CONDITIONAL) ||
      (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_MISS_CONDITIONAL) ||
      (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_HIT_SERVED)) {
    // its a cache hit.
    if (via_string[VIA_CACHE_RESULT] == VIA_IN_RAM_CACHE_FRESH) {
      hit_miss_code = SQUID_HIT_RAM;
    } else if (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_RWW_HIT) {
      hit_miss_code = SQUID_HIT_RWW;
    } else { // TODO: Support other cache tiers here
      hit_miss_code = SQUID_HIT_RESERVED;
    }
  } else {
    auto reason{header->reason_get()};

    if (!reason.empty() && reason.length() >= 24 && reason[0] == '!' && reason[1] == SQUID_HIT_RESERVED) {
      hit_miss_code = SQUID_HIT_RESERVED;
      // its a miss in the cache. find out why.
    } else if (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_MISS_EXPIRED) {
      hit_miss_code = SQUID_MISS_PRE_EXPIRED;
    } else if (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_MISS_CONFIG) {
      hit_miss_code = SQUID_MISS_NONE;
    } else if (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_MISS_CLIENT) {
      hit_miss_code = SQUID_MISS_PRAGMA_NOCACHE;
    } else if (via_string[VIA_DETAIL_CACHE_LOOKUP] == VIA_DETAIL_MISS_METHOD) {
      hit_miss_code = SQUID_MISS_HTTP_NON_CACHE;
    } else if (via_string[VIA_CLIENT_REQUEST] == VIA_CLIENT_ERROR) {
      hit_miss_code = SQUID_MISS_ERROR;
    } else if (via_string[VIA_CLIENT_REQUEST] == VIA_CLIENT_NO_CACHE) {
      hit_miss_code = SQUID_MISS_PRAGMA_NOCACHE;
    } else {
      hit_miss_code = SQUID_MISS_NONE;
    }
  }

  //////////////////////
  // Now the Log Code //
  //////////////////////
  if (via_string[VIA_CLIENT_REQUEST] == VIA_CLIENT_NO_CACHE) {
    log_code = SquidLogCode::TCP_CLIENT_REFRESH;
  }

  else {
    if (via_string[VIA_CLIENT_REQUEST] == VIA_CLIENT_IMS) {
      if ((via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_FRESH) || (via_string[VIA_CACHE_RESULT] == VIA_IN_RAM_CACHE_FRESH) ||
          (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_RWW_HIT)) {
        log_code = SquidLogCode::TCP_IMS_HIT;
      } else {
        if (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_STALE && via_string[VIA_SERVER_RESULT] == VIA_SERVER_NOT_MODIFIED) {
          log_code = SquidLogCode::TCP_REFRESH_HIT;
        } else {
          log_code = SquidLogCode::TCP_IMS_MISS;
        }
      }
    }

    else {
      if (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_STALE) {
        if (via_string[VIA_SERVER_RESULT] == VIA_SERVER_NOT_MODIFIED) {
          log_code = SquidLogCode::TCP_REFRESH_HIT;
        } else {
          if (via_string[VIA_SERVER_RESULT] == VIA_SERVER_ERROR) {
            log_code = SquidLogCode::TCP_REF_FAIL_HIT;
          } else {
            log_code = SquidLogCode::TCP_REFRESH_MISS;
          }
        }
      } else {
        if (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_FRESH) {
          log_code = SquidLogCode::TCP_HIT;
        } else if (via_string[VIA_CACHE_RESULT] == VIA_IN_RAM_CACHE_FRESH) {
          log_code = SquidLogCode::TCP_MEM_HIT;
        } else if (via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_RWW_HIT) {
          log_code = SquidLogCode::TCP_CF_HIT; // Read while write HIT
        } else {
          log_code = SquidLogCode::TCP_MISS;
        }
      }
    }
  }

  ////////////////////////
  // The Hierarchy Code //
  ////////////////////////
  if ((via_string[VIA_CACHE_RESULT] == VIA_IN_CACHE_FRESH) || (via_string[VIA_CACHE_RESULT] == VIA_IN_RAM_CACHE_FRESH)) {
    hier_code = SquidHierarchyCode::NONE;
  } else if (via_string[VIA_DETAIL_PP_CONNECT] == VIA_DETAIL_PP_SUCCESS) {
    hier_code = SquidHierarchyCode::PARENT_HIT;
  } else if (via_string[VIA_DETAIL_CACHE_TYPE] == VIA_DETAIL_PARENT) {
    hier_code = SquidHierarchyCode::DEFAULT_PARENT;
  } else if (via_string[VIA_DETAIL_TUNNEL] == VIA_DETAIL_TUNNEL_NO_FORWARD) {
    hier_code = SquidHierarchyCode::NONE;
  } else {
    hier_code = SquidHierarchyCode::DIRECT;
  }

  // Errors may override the other codes, so check the via string error codes last
  switch (via_string[VIA_ERROR_TYPE]) {
  case VIA_ERROR_AUTHORIZATION:
    log_code = SquidLogCode::ERR_PROXY_DENIED;
    break;
  case VIA_ERROR_CONNECTION:
    if (log_code == SquidLogCode::TCP_MISS || log_code == SquidLogCode::TCP_REFRESH_MISS) {
      log_code = SquidLogCode::ERR_CONNECT_FAIL;
    }
    break;
  case VIA_ERROR_DNS_FAILURE:
    log_code  = SquidLogCode::ERR_DNS_FAIL;
    hier_code = SquidHierarchyCode::NONE;
    break;
  case VIA_ERROR_FORBIDDEN:
    log_code = SquidLogCode::ERR_PROXY_DENIED;
    break;
  case VIA_ERROR_HEADER_SYNTAX:
    log_code  = SquidLogCode::ERR_INVALID_REQ;
    hier_code = SquidHierarchyCode::NONE;
    break;
  case VIA_ERROR_SERVER:
    if (log_code == SquidLogCode::TCP_MISS || log_code == SquidLogCode::TCP_IMS_MISS) {
      log_code = SquidLogCode::ERR_CONNECT_FAIL;
    }
    break;
  case VIA_ERROR_TIMEOUT:
    if (log_code == SquidLogCode::TCP_MISS || log_code == SquidLogCode::TCP_IMS_MISS) {
      log_code = SquidLogCode::ERR_READ_TIMEOUT;
    }
    if (hier_code == SquidHierarchyCode::PARENT_HIT) {
      hier_code = SquidHierarchyCode::TIMEOUT_PARENT_HIT;
    } else {
      hier_code = SquidHierarchyCode::TIMEOUT_DIRECT;
    }
    break;
  case VIA_ERROR_CACHE_READ:
    log_code  = SquidLogCode::TCP_SWAPFAIL;
    hier_code = SquidHierarchyCode::NONE;
    break;
  case VIA_ERROR_LOOP_DETECTED:
    log_code  = SquidLogCode::ERR_LOOP_DETECTED;
    hier_code = SquidHierarchyCode::NONE;
    break;
  case VIA_ERROR_UNKNOWN:
    log_code  = SquidLogCode::ERR_UNKNOWN;
    hier_code = SquidHierarchyCode::NONE;
    break;
  default:
    break;
  }

  squid_codes->log_code      = log_code;
  squid_codes->hier_code     = hier_code;
  squid_codes->hit_miss_code = hit_miss_code;
}

#include "proxy/http/HttpDebugNames.h"

void
HttpTransactHeaders::insert_warning_header(HttpConfigParams *http_config_param, HTTPHdr *header, HTTPWarningCode code,
                                           const char *warn_text, int warn_text_len)
{
  int bufsize, len;

  // + 23 for 20 possible digits of warning code (long long max
  //  digits) & 2 spaces & the string terminator
  bufsize = http_config_param->proxy_response_via_string_len + 23;
  if (warn_text != nullptr) {
    bufsize += warn_text_len;
  } else {
    warn_text_len = 0; // Make sure it's really zero
  }

  char *warning_text = static_cast<char *>(alloca(bufsize));

  len = snprintf(warning_text, bufsize, "%3d %s %.*s", static_cast<int>(code), http_config_param->proxy_response_via_string,
                 warn_text_len, warn_text);
  header->value_set(static_cast<std::string_view>(MIME_FIELD_WARNING),
                    std::string_view{warning_text, static_cast<std::string_view::size_type>(len)});
}

void
HttpTransactHeaders::insert_time_and_age_headers_in_response(ink_time_t request_sent_time, ink_time_t response_received_time,
                                                             ink_time_t now, HTTPHdr *base, HTTPHdr *outgoing)
{
  ink_time_t date        = base->get_date();
  ink_time_t current_age = HttpTransactCache::calculate_document_age(request_sent_time, response_received_time, base, date, now);

  outgoing->set_age(current_age); // set_age() deals with overflow properly, so pass it along

  // FIX: should handle missing date when response is received, not here.
  //      See INKqa09852.
  if (date <= 0) {
    outgoing->set_date(now);
  }
}

/// write the protocol stack to the @a via_string.
/// If @a detailed then do the full stack, otherwise just the "top level" protocol.
/// Returns the number of characters appended to hdr_string (no nul appended).
int
HttpTransactHeaders::write_hdr_protocol_stack(char *hdr_string, size_t len, ProtocolStackDetail pSDetail,
                                              std::string_view *proto_buf, int n_proto, char separator)
{
  char *hdr   = hdr_string; // keep original pointer for size computation later.
  char *limit = hdr_string + len;

  if (n_proto <= 0 || hdr == nullptr || len <= 0) {
    // nothing
  } else if (ProtocolStackDetail::Full == pSDetail) {
    for (std::string_view *v = proto_buf, *v_limit = proto_buf + n_proto; v < v_limit && (hdr + v->size() + 1) < limit; ++v) {
      if (v != proto_buf) {
        *hdr++ = separator;
      }
      memcpy(hdr, v->data(), v->size());
      hdr += v->size();
    }
  } else {
    std::string_view *proto_end  = proto_buf + n_proto;
    bool              http_1_0_p = std::find(proto_buf, proto_end, IP_PROTO_TAG_HTTP_1_0) != proto_end;
    bool              http_1_1_p = std::find(proto_buf, proto_end, IP_PROTO_TAG_HTTP_1_1) != proto_end;

    if ((http_1_0_p || http_1_1_p) && hdr + 10 < limit) {
      bool tls_p = std::find_if(proto_buf, proto_end, [](std::string_view tag) { return IsPrefixOf("tls/"sv, tag); }) != proto_end;

      memcpy(hdr, "http", 4);
      hdr += 4;
      if (tls_p) {
        *hdr++ = 's';
      }

      // If detail level is compact (RFC 7239 compliant "proto" value for Forwarded field), stop here.

      if (ProtocolStackDetail::Standard == pSDetail) {
        *hdr++        = '/';
        bool http_2_p = std::find(proto_buf, proto_end, IP_PROTO_TAG_HTTP_2_0) != proto_end;
        bool http_3_p = std::find(proto_buf, proto_end, IP_PROTO_TAG_HTTP_3) != proto_end;
        if (http_2_p) {
          *hdr++ = '2';
        } else if (http_3_p) {
          *hdr++ = '3';
        } else if (http_1_0_p) {
          memcpy(hdr, "1.0", 3);
          hdr += 3;
        } else if (http_1_1_p) {
          memcpy(hdr, "1.1", 3);
          hdr += 3;
        }
      }
    }
  }
  return hdr - hdr_string;
}

///////////////////////////////////////////////////////////////////////////////
// Name       : insert_via_header_in_request
// Description: takes in existing via_string and inserts it in header
//
// Input      :
// Output     :
//
// Details    :
//
// [u<client-stuff> l<cache-lookup-stuff> o<server-stuff> f<cache-fill-stuff> p<proxy-stuff>]
//
//      client stuff
//              I       IMS
//              N       no-cache
//              A       accept headers
//              C       cookie
//
//      cache lookup stuff
//              M       miss
//              A       in cache, not acceptable
//              S       in cache, stale
//              H       in cache, fresh
//
//      server stuff
//              N       not-modified
//              S       served
//
//      cache fill stuff
//              F       filled into cache
//              U       updated cache
//
//      proxy stuff
//              N       not-modified
//              S       served
//              R       origin server revalidated
//
// For example:
//
//      [u lH o f pS]      cache hit
//      [u lM oS fF pS]    cache miss
//      [uN l oS f pS]     no-cache origin server fetch
//
//
///////////////////////////////////////////////////////////////////////////////
void
HttpTransactHeaders::insert_via_header_in_request(HttpTransact::State *s, HTTPHdr *header)
{
  char  new_via_string[1024]; // 512-bytes for hostname+via string, 512-bytes for the debug info
  char *via_string = new_via_string;
  char *via_limit  = via_string + sizeof(new_via_string);

  if ((s->http_config_param->proxy_hostname_len + s->http_config_param->proxy_request_via_string_len) > 512) {
    header->value_append(static_cast<std::string_view>(MIME_FIELD_VIA), "TrafficServer"sv, true);
    return;
  }

  char                            *incoming_via = s->via_string;
  std::array<std::string_view, 10> proto_buf; // 10 seems like a reasonable number of protos to print
  int                              n_proto = s->state_machine->populate_client_protocol(proto_buf.data(), proto_buf.size());

  via_string +=
    write_hdr_protocol_stack(via_string, via_limit - via_string, ProtocolStackDetail::Standard, proto_buf.data(), n_proto);
  *via_string++ = ' ';

  via_string += nstrcpy(via_string, s->http_config_param->proxy_hostname);

  *via_string++ = '[';
  memcpy(via_string, Machine::instance()->process_uuid.getString(), TS_UUID_STRING_LEN);
  via_string    += TS_UUID_STRING_LEN;
  *via_string++  = ']';
  *via_string++  = ' ';
  *via_string++  = '(';

  memcpy(via_string, s->http_config_param->proxy_request_via_string, s->http_config_param->proxy_request_via_string_len);
  via_string += s->http_config_param->proxy_request_via_string_len;

  if (s->txn_conf->insert_request_via_string > 1) {
    *via_string++ = ' ';
    *via_string++ = '[';

    // incoming_via can be max MAX_VIA_INDICES+1 long (i.e. around 25 or so)
    if (s->txn_conf->insert_request_via_string > 2) { // Highest verbosity
      via_string += nstrcpy(via_string, incoming_via);
    } else {
      memcpy(via_string, incoming_via + VIA_CLIENT, VIA_SERVER - VIA_CLIENT);
      via_string += VIA_SERVER - VIA_CLIENT;
    }
    *via_string++ = ']';

    // reserve 4 for " []" and 3 for "])".
    if (via_limit - via_string > 4 && s->txn_conf->insert_request_via_string > 3) { // Ultra highest verbosity
      *via_string++ = ' ';
      *via_string++ = '[';
      via_string +=
        write_hdr_protocol_stack(via_string, via_limit - via_string - 3, ProtocolStackDetail::Full, proto_buf.data(), n_proto);
      *via_string++ = ']';
    }
  }

  *via_string++ = ')';
  *via_string   = 0;

  ink_assert((size_t)(via_string - new_via_string) < (sizeof(new_via_string) - 1));
  header->value_append(static_cast<std::string_view>(MIME_FIELD_VIA),
                       std::string_view{new_via_string, static_cast<std::string_view::size_type>(via_string - new_via_string)},
                       true);
}

void
HttpTransactHeaders::insert_hsts_header_in_response(HttpTransact::State *s, HTTPHdr *header)
{
  char           new_hsts_string[64];
  char          *hsts_string          = new_hsts_string;
  constexpr char include_subdomains[] = "; includeSubDomains";

  // add max-age
  int length = snprintf(new_hsts_string, sizeof(new_hsts_string), "max-age=%" PRId64, s->txn_conf->proxy_response_hsts_max_age);

  // add include subdomain if set
  if (s->txn_conf->proxy_response_hsts_include_subdomains) {
    hsts_string += length;
    memcpy(hsts_string, include_subdomains, sizeof(include_subdomains) - 1);
    length += sizeof(include_subdomains) - 1;
  }

  header->value_set(static_cast<std::string_view>(MIME_FIELD_STRICT_TRANSPORT_SECURITY),
                    std::string_view{new_hsts_string, static_cast<std::string_view::size_type>(length)});
}

void
HttpTransactHeaders::insert_via_header_in_response(HttpTransact::State *s, HTTPHdr *header)
{
  char  new_via_string[HTTP_OUR_VIA_MAX_LENGTH];
  char *via_string = new_via_string;
  char *via_limit  = via_string + sizeof(new_via_string);

  if ((s->http_config_param->proxy_hostname_len + s->http_config_param->proxy_response_via_string_len) > 512) {
    header->value_append(static_cast<std::string_view>(MIME_FIELD_VIA), "TrafficServer"sv, true);
    return;
  }

  char                            *incoming_via = s->via_string;
  std::array<std::string_view, 10> proto_buf; // 10 seems like a reasonable number of protos to print
  int                              n_proto = 0;

  // Should suffice - if we're adding a response VIA, the connection is HTTP and only 1.0 and 1.1 are supported outbound.
  // TODO H2 expand for HTTP/2 outbound
  proto_buf[n_proto++] = header->version_get().get_minor() == 0 ? IP_PROTO_TAG_HTTP_1_0 : IP_PROTO_TAG_HTTP_1_1;

  auto ss = s->state_machine->get_server_txn();
  if (ss) {
    n_proto += ss->populate_protocol(proto_buf.data() + n_proto, proto_buf.size() - n_proto);
  }
  via_string +=
    write_hdr_protocol_stack(via_string, via_limit - via_string, ProtocolStackDetail::Standard, proto_buf.data(), n_proto);
  *via_string++ = ' ';

  via_string    += nstrcpy(via_string, s->http_config_param->proxy_hostname);
  *via_string++  = ' ';
  *via_string++  = '(';

  memcpy(via_string, s->http_config_param->proxy_response_via_string, s->http_config_param->proxy_response_via_string_len);
  via_string += s->http_config_param->proxy_response_via_string_len;

  if (s->txn_conf->insert_response_via_string > 1) {
    *via_string++ = ' ';
    *via_string++ = '[';

    // incoming_via can be max MAX_VIA_INDICES+1 long (i.e. around 25 or so)
    if (s->txn_conf->insert_response_via_string > 2) { // Highest verbosity
      via_string += nstrcpy(via_string, incoming_via);
    } else {
      memcpy(via_string, incoming_via + VIA_CACHE, VIA_PROXY - VIA_CACHE);
      via_string += VIA_PROXY - VIA_CACHE;
    }
    *via_string++ = ']';

    if (via_limit - via_string > 4 && s->txn_conf->insert_response_via_string > 3) { // Ultra highest verbosity
      *via_string++ = ' ';
      *via_string++ = '[';
      via_string +=
        write_hdr_protocol_stack(via_string, via_limit - via_string - 3, ProtocolStackDetail::Full, proto_buf.data(), n_proto);
      *via_string++ = ']';
    }
  }

  *via_string++ = ')';
  *via_string   = 0;

  ink_assert((size_t)(via_string - new_via_string) < (sizeof(new_via_string) - 1));
  header->value_append(static_cast<std::string_view>(MIME_FIELD_VIA),
                       std::string_view{new_via_string, static_cast<std::string_view::size_type>(via_string - new_via_string)},
                       true);
}

void
HttpTransactHeaders::remove_conditional_headers(HTTPHdr *outgoing)
{
  if (outgoing->presence(MIME_PRESENCE_IF_MODIFIED_SINCE | MIME_PRESENCE_IF_UNMODIFIED_SINCE | MIME_PRESENCE_IF_MATCH |
                         MIME_PRESENCE_IF_NONE_MATCH)) {
    outgoing->field_delete(static_cast<std::string_view>(MIME_FIELD_IF_MODIFIED_SINCE));
    outgoing->field_delete(static_cast<std::string_view>(MIME_FIELD_IF_UNMODIFIED_SINCE));
    outgoing->field_delete(static_cast<std::string_view>(MIME_FIELD_IF_MATCH));
    outgoing->field_delete(static_cast<std::string_view>(MIME_FIELD_IF_NONE_MATCH));
  }
  // TODO: how about RANGE and IF_RANGE?
}

void
HttpTransactHeaders::remove_100_continue_headers(HttpTransact::State *s, HTTPHdr *outgoing)
{
  auto expect{s->hdr_info.client_request.value_get(static_cast<std::string_view>(MIME_FIELD_EXPECT))};

  if (strcasecmp(expect, static_cast<std::string_view>(HTTP_VALUE_100_CONTINUE)) == 0) {
    outgoing->field_delete(static_cast<std::string_view>(MIME_FIELD_EXPECT));
  }
}

////////////////////////////////////////////////////////////////////////
// Deal with lame-o servers by removing the host name from the url.
void
HttpTransactHeaders::remove_host_name_from_url(HTTPHdr *outgoing_request)
{
  URL *outgoing_url = outgoing_request->url_get();
  outgoing_url->nuke_proxy_stuff();
}

void
HttpTransactHeaders::add_global_user_agent_header_to_request(const OverridableHttpConfigParams *http_txn_conf, HTTPHdr *header)
{
  if (http_txn_conf->global_user_agent_header) {
    MIMEField *ua_field;

    Dbg(dbg_ctl_http_trans, "Adding User-Agent: %.*s", static_cast<int>(http_txn_conf->global_user_agent_header_size),
        http_txn_conf->global_user_agent_header);
    if ((ua_field = header->field_find(static_cast<std::string_view>(MIME_FIELD_USER_AGENT))) == nullptr) {
      if (likely((ua_field = header->field_create(static_cast<std::string_view>(MIME_FIELD_USER_AGENT))) != nullptr)) {
        header->field_attach(ua_field);
      }
    }
    // This will remove any old string (free it), and set our User-Agent.
    if (likely(ua_field)) {
      header->field_value_set(
        ua_field, std::string_view{http_txn_conf->global_user_agent_header, http_txn_conf->global_user_agent_header_size});
    }
  }
}

void
HttpTransactHeaders::add_forwarded_field_to_request(HttpTransact::State *s, HTTPHdr *request)
{
  HttpForwarded::OptionBitSet optSet = s->txn_conf->insert_forwarded;

  if (optSet.any()) { // One or more Forwarded parameters enabled, so insert/append to Forwarded header.

    swoc::LocalBufferWriter<1024> hdr;

    IpEndpoint src_addr = s->client_info.src_addr;
    if (s->state_machine->get_ua_txn() && s->state_machine->get_ua_txn()->get_netvc()) {
      const ProxyProtocol &pp = s->state_machine->get_ua_txn()->get_netvc()->get_proxy_protocol_info();

      if (pp.version != ProxyProtocolVersion::UNDEFINED) {
        src_addr = pp.src_addr;
      }
    }

    if (optSet[HttpForwarded::FOR] and ats_is_ip(&src_addr.sa)) {
      // NOTE:  The logic within this if statement assumes that hdr is empty at this point.

      hdr << "for=";

      bool is_ipv6 = ats_is_ip6(&src_addr.sa);

      if (is_ipv6) {
        hdr << "\"[";
      }

      if (ats_ip_ntop(&src_addr.sa, hdr.aux_data(), hdr.remaining()) == nullptr) {
        Dbg(dbg_ctl_http_trans, "[add_forwarded_field_to_outgoing_request] ats_ip_ntop() call failed");
        return;
      }

      // Fail-safe.
      hdr.aux_data()[hdr.remaining() - 1] = '\0';

      hdr.commit(strlen(hdr.aux_data()));

      if (is_ipv6) {
        hdr << "]\"";
      }
    }

    if (optSet[HttpForwarded::BY_UNKNOWN]) {
      if (hdr.size()) {
        hdr << ';';
      }

      hdr << "by=unknown";
    }

    if (optSet[HttpForwarded::BY_SERVER_NAME]) {
      if (hdr.size()) {
        hdr << ';';
      }

      hdr << "by=" << s->http_config_param->proxy_hostname;
    }

    const Machine &m = *Machine::instance();

    if (optSet[HttpForwarded::BY_UUID] and m.process_uuid.valid()) {
      if (hdr.size()) {
        hdr << ';';
      }

      hdr << "by=_" << m.process_uuid.getString();
    }

    if (optSet[HttpForwarded::BY_IP] and m.ip.isValid()) {
      if (hdr.size()) {
        hdr << ';';
      }

      hdr << "by=";

      bool is_ipv6 = ats_is_ip6(&s->client_info.dst_addr.sa);

      if (is_ipv6) {
        hdr << "\"[";
      }

      if (ats_ip_ntop(&s->client_info.dst_addr.sa, hdr.aux_data(), hdr.remaining()) == nullptr) {
        Dbg(dbg_ctl_http_trans, "[add_forwarded_field_to_outgoing_request] ats_ip_ntop() call failed");
        return;
      }

      // Fail-safe.
      hdr.aux_data()[hdr.remaining() - 1] = '\0';

      hdr.commit(strlen(hdr.aux_data()));

      if (is_ipv6) {
        hdr << "]\"";
      }
    }

    std::array<std::string_view, 10> protoBuf;    // 10 seems like a reasonable number of protos to print
    int                              n_proto = 0; // Indulge clang's incorrect claim that this need to be initialized.

    static const HttpForwarded::OptionBitSet OptionsNeedingProtocol = HttpForwarded::OptionBitSet()
                                                                        .set(HttpForwarded::PROTO)
                                                                        .set(HttpForwarded::CONNECTION_COMPACT)
                                                                        .set(HttpForwarded::CONNECTION_STD)
                                                                        .set(HttpForwarded::CONNECTION_FULL);

    if ((optSet bitand OptionsNeedingProtocol).any()) {
      n_proto = s->state_machine->populate_client_protocol(protoBuf.data(), protoBuf.size());
    }

    if (optSet[HttpForwarded::PROTO] and (n_proto > 0)) {
      if (hdr.size()) {
        hdr << ';';
      }

      hdr << "proto=";

      int numChars = HttpTransactHeaders::write_hdr_protocol_stack(hdr.aux_data(), hdr.remaining(), ProtocolStackDetail::Compact,
                                                                   protoBuf.data(), n_proto, '-');
      if (numChars > 0) {
        hdr.commit(size_t(numChars));
      }
    }

    if (optSet[HttpForwarded::HOST]) {
      const MIMEField *hostField = s->hdr_info.client_request.field_find(static_cast<std::string_view>(MIME_FIELD_HOST));

      if (hostField and hostField->m_len_value) {
        std::string_view hSV{hostField->m_ptr_value, hostField->m_len_value};

        bool needsDoubleQuotes = hSV.find(':') != std::string_view::npos;

        if (hdr.size()) {
          hdr << ';';
        }

        hdr << "host=";
        if (needsDoubleQuotes) {
          hdr << '"';
        }
        hdr << hSV;
        if (needsDoubleQuotes) {
          hdr << '"';
        }
      }
    }

    if (n_proto > 0) {
      auto Conn = [&](HttpForwarded::Option opt, HttpTransactHeaders::ProtocolStackDetail detail) -> void {
        if (optSet[opt] && hdr.remaining() > 0) {
          swoc::FixedBufferWriter lw{hdr.aux_data(), hdr.remaining()};

          if (hdr.size()) {
            lw << ';';
          }

          lw << "connection=";

          int numChars =
            HttpTransactHeaders::write_hdr_protocol_stack(lw.aux_data(), lw.remaining(), detail, protoBuf.data(), n_proto, '-');
          if (numChars > 0 && !(lw.commit(size_t(numChars)), lw.error())) {
            hdr.commit(lw.size());
          }
        }
      };

      Conn(HttpForwarded::CONNECTION_COMPACT, HttpTransactHeaders::ProtocolStackDetail::Compact);
      Conn(HttpForwarded::CONNECTION_STD, HttpTransactHeaders::ProtocolStackDetail::Standard);
      Conn(HttpForwarded::CONNECTION_FULL, HttpTransactHeaders::ProtocolStackDetail::Full);
    }

    // Add or append to the Forwarded header.  As a fail-safe against corrupting the MIME header, don't add Forwarded if
    // it's size is exactly the capacity of the buffer.
    //
    if (hdr.size() and !hdr.error() and (hdr.size() < hdr.capacity())) {
      std::string_view sV = hdr.view();

      request->value_append(static_cast<std::string_view>(MIME_FIELD_FORWARDED), sV, true, ','); // true => separator must
                                                                                                 // be inserted

      Dbg(dbg_ctl_http_trans, "[add_forwarded_field_to_outgoing_request] Forwarded header (%.*s) added",
          static_cast<int>(hdr.size()), hdr.data());
    }
  }

} // end HttpTransact::add_forwarded_field_to_outgoing_request()

void
HttpTransactHeaders::add_server_header_to_response(const OverridableHttpConfigParams *http_txn_conf, HTTPHdr *header)
{
  if (http_txn_conf->proxy_response_server_enabled && http_txn_conf->proxy_response_server_string) {
    MIMEField *ua_field;
    bool       do_add = true;

    if ((ua_field = header->field_find(static_cast<std::string_view>(MIME_FIELD_SERVER))) == nullptr) {
      if (likely((ua_field = header->field_create(static_cast<std::string_view>(MIME_FIELD_SERVER))) != nullptr)) {
        header->field_attach(ua_field);
      }
    } else {
      // There was an existing header from Origin, so only add if setting allows to overwrite.
      do_add = (1 == http_txn_conf->proxy_response_server_enabled);
    }

    // This will remove any old string (free it), and set our Server header.
    if (do_add && likely(ua_field)) {
      Dbg(dbg_ctl_http_trans, "Adding Server: %s", http_txn_conf->proxy_response_server_string);
      header->field_value_set(
        ua_field, std::string_view{http_txn_conf->proxy_response_server_string, http_txn_conf->proxy_response_server_string_len});
    }
  }
}

void
HttpTransactHeaders::remove_privacy_headers_from_request(HttpConfigParams                  *http_config_param,
                                                         const OverridableHttpConfigParams *http_txn_conf, HTTPHdr *header)
{
  if (!header) {
    return;
  }

  // From
  if (http_txn_conf->anonymize_remove_from) {
    Dbg(dbg_ctl_anon, "removing 'From' headers");
    header->field_delete(static_cast<std::string_view>(MIME_FIELD_FROM));
  }
  // Referer
  if (http_txn_conf->anonymize_remove_referer) {
    Dbg(dbg_ctl_anon, "removing 'Referer' headers");
    header->field_delete(static_cast<std::string_view>(MIME_FIELD_REFERER));
  }
  // User-Agent
  if (http_txn_conf->anonymize_remove_user_agent) {
    Dbg(dbg_ctl_anon, "removing 'User-agent' headers");
    header->field_delete(static_cast<std::string_view>(MIME_FIELD_USER_AGENT));
  }
  // Cookie
  if (http_txn_conf->anonymize_remove_cookie) {
    Dbg(dbg_ctl_anon, "removing 'Cookie' headers");
    header->field_delete(static_cast<std::string_view>(MIME_FIELD_COOKIE));
  }
  // Client-ip
  if (http_txn_conf->anonymize_remove_client_ip) {
    Dbg(dbg_ctl_anon, "removing 'Client-ip' headers");
    header->field_delete(static_cast<std::string_view>(MIME_FIELD_CLIENT_IP));
  }
  /////////////////////////////////////////////
  // remove any other user specified headers //
  /////////////////////////////////////////////

  // FIXME: we shouldn't parse this list every time, only when the
  // FIXME: config file changes.
  if (http_config_param->anonymize_other_header_list) {
    Str        *field;
    StrList     anon_list(false);
    const char *anon_string;

    anon_string = http_config_param->anonymize_other_header_list;
    Dbg(dbg_ctl_anon, "removing other headers (%s)", anon_string);
    HttpCompat::parse_comma_list(&anon_list, anon_string);
    for (field = anon_list.head; field != nullptr; field = field->next) {
      Dbg(dbg_ctl_anon, "removing '%s' headers", field->str);
      header->field_delete(std::string_view{field->str, field->len});
    }
  }
}

void
HttpTransactHeaders::normalize_accept_encoding(const OverridableHttpConfigParams *ohcp, HTTPHdr *header)
{
  int normalize_ae = ohcp->normalize_ae;

  if (normalize_ae) {
    MIMEField *ae_field = header->field_find(static_cast<std::string_view>(MIME_FIELD_ACCEPT_ENCODING));

    if (ae_field) {
      if (normalize_ae == 1) {
        // Force Accept-Encoding header to gzip or no header.
        if (HttpTransactCache::match_content_encoding(ae_field, "gzip")) {
          header->field_value_set(ae_field, "gzip"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to gzip");
        } else {
          header->field_delete(ae_field);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] removed non-gzip Accept-Encoding");
        }
      } else if (normalize_ae == 2) {
        // Force Accept-Encoding header to br (Brotli) or no header.
        if (HttpTransactCache::match_content_encoding(ae_field, "br")) {
          header->field_value_set(ae_field, "br"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to br");
        } else if (HttpTransactCache::match_content_encoding(ae_field, "gzip")) {
          header->field_value_set(ae_field, "gzip"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to gzip");
        } else {
          header->field_delete(ae_field);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] removed non-br Accept-Encoding");
        }
      } else if (normalize_ae == 3) {
        // Force Accept-Encoding header to br,gzip, or br, or gzip, or no header.
        if (HttpTransactCache::match_content_encoding(ae_field, "br") &&
            HttpTransactCache::match_content_encoding(ae_field, "gzip")) {
          header->field_value_set(ae_field, "br, gzip"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to br, gzip");
        } else if (HttpTransactCache::match_content_encoding(ae_field, "br")) {
          header->field_value_set(ae_field, "br"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to br");
        } else if (HttpTransactCache::match_content_encoding(ae_field, "gzip")) {
          header->field_value_set(ae_field, "gzip"sv);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] normalized Accept-Encoding to gzip");
        } else {
          header->field_delete(ae_field);
          Dbg(dbg_ctl_http_trans, "[Headers::normalize_accept_encoding] removed non-br non-gzip Accept-Encoding");
        }
      } else {
        static bool logged = false;

        if (!logged) {
          Error("proxy.config.http.normalize_ae value out of range");
          logged = true;
        }
      }
    }
  }
}

void
HttpTransactHeaders::add_connection_close(HTTPHdr *header)
{
  MIMEField *field = header->field_find(static_cast<std::string_view>(MIME_FIELD_CONNECTION));
  if (!field) {
    field = header->field_create(static_cast<std::string_view>(MIME_FIELD_CONNECTION));
    header->field_attach(field);
  }
  header->field_value_set(field, static_cast<std::string_view>(HTTP_VALUE_CLOSE));
}
