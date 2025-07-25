/*
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
//////////////////////////////////////////////////////////////////////////////////////////////
// operators.cc: implementation of the operator classes
//
//
#include <arpa/inet.h>
#include <cstring>
#include <algorithm>
#include <iomanip>

#include "records/RecCore.h"
#include "ts/ts.h"
#include "swoc/swoc_file.h"

#include "operators.h"
#include "ts/apidefs.h"

namespace
{
const unsigned int LOCAL_IP_ADDRESS = 0x0100007f;
const unsigned int MAX_SIZE         = 256;
const int          LOCAL_PORT       = 8080;

int
handleFetchEvents(TSCont cont, TSEvent event, void *edata)
{
  TSHttpTxn http_txn = static_cast<TSHttpTxn>(TSContDataGet(cont));

  switch (static_cast<int>(event)) {
  case OperatorSetBodyFrom::TS_EVENT_FETCHSM_SUCCESS: {
    TSHttpTxn   fetchsm_txn = static_cast<TSHttpTxn>(edata);
    int         data_len;
    const char *data_start = TSFetchRespGet(fetchsm_txn, &data_len);
    if (data_start && (data_len > 0)) {
      const char  *data_end = data_start + data_len;
      TSHttpParser parser   = TSHttpParserCreate();
      TSMBuffer    hdr_buf  = TSMBufferCreate();
      TSMLoc       hdr_loc  = TSHttpHdrCreate(hdr_buf);
      TSHttpHdrTypeSet(hdr_buf, hdr_loc, TS_HTTP_TYPE_RESPONSE);
      if (TSHttpHdrParseResp(parser, hdr_buf, hdr_loc, &data_start, data_end) == TS_PARSE_DONE) {
        TSHttpTxnErrorBodySet(http_txn, TSstrdup(data_start), (data_end - data_start), nullptr);
      } else {
        TSWarning("[%s] Unable to parse set-custom-body fetch response", __FUNCTION__);
      }
      TSHttpParserDestroy(parser);
      TSHandleMLocRelease(hdr_buf, nullptr, hdr_loc);
      TSMBufferDestroy(hdr_buf);
    } else {
      TSWarning("[%s] Successful set-custom-body fetch did not result in any content", __FUNCTION__);
    }
    TSHttpTxnReenable(http_txn, TS_EVENT_HTTP_ERROR);
  } break;
  case OperatorSetBodyFrom::TS_EVENT_FETCHSM_FAILURE: {
    Dbg(pi_dbg_ctl, "OperatorSetBodyFrom: Error getting custom body");
    TSHttpTxnReenable(http_txn, TS_EVENT_HTTP_CONTINUE);
  } break;
  case OperatorSetBodyFrom::TS_EVENT_FETCHSM_TIMEOUT: {
    Dbg(pi_dbg_ctl, "OperatorSetBodyFrom: Timeout getting custom body");
    TSHttpTxnReenable(http_txn, TS_EVENT_HTTP_CONTINUE);
  } break;
  case TS_EVENT_HTTP_TXN_CLOSE: {
    TSContDestroy(cont);
    TSHttpTxnReenable(http_txn, TS_EVENT_HTTP_CONTINUE);
  } break;
  default:
    TSError("[%s] handleFetchEvents got unknown event: %d", PLUGIN_NAME, event);
    break;
  }
  return 0;
}

TSReturnCode
createRequestString(const std::string_view &value, char (&req_buf)[MAX_SIZE], int *req_buf_size)
{
  const char *start = value.data();
  const char *end   = start + value.size();
  TSMLoc      url_loc;
  TSMBuffer   url_buf = TSMBufferCreate();
  int         host_len, url_len = 0;

  if (TSUrlCreate(url_buf, &url_loc) == TS_SUCCESS && TSUrlParse(url_buf, url_loc, &start, end) == TS_PARSE_DONE) {
    const char *host = TSUrlHostGet(url_buf, url_loc, &host_len);
    const char *url  = TSUrlStringGet(url_buf, url_loc, &url_len);

    *req_buf_size = snprintf(req_buf, MAX_SIZE, "GET %.*s HTTP/1.1\r\nHost: %.*s\r\n\r\n", url_len, url, host_len, host);

    TSMBufferDestroy(url_buf);

    return TS_SUCCESS;
  } else {
    Dbg(pi_dbg_ctl, "Failed to parse url %s", start);
    TSMBufferDestroy(url_buf);
    return TS_ERROR;
  }
}

} // namespace

// OperatorConfig
void
OperatorSetConfig::initialize(Parser &p)
{
  Operator::initialize(p);
  _config = p.get_arg();

  if (TS_SUCCESS == TSHttpTxnConfigFind(_config.c_str(), _config.size(), &_key, &_type)) {
    _value.set_value(p.get_value());
  } else {
    _key = TS_CONFIG_NULL;
    TSError("[%s] no such records config: %s", PLUGIN_NAME, _config.c_str());
  }
}

bool
OperatorSetConfig::exec(const Resources &res) const
{
  if (TS_CONFIG_NULL != _key) {
    switch (_type) {
    case TS_RECORDDATATYPE_INT:
      if (TS_SUCCESS == TSHttpTxnConfigIntSet(res.txnp, _key, _value.get_int_value())) {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invoked on %s=%d", _config.c_str(), _value.get_int_value());
      } else {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invocation failed on %s=%d", _config.c_str(), _value.get_int_value());
      }
      break;
    case TS_RECORDDATATYPE_FLOAT:
      if (TS_SUCCESS == TSHttpTxnConfigFloatSet(res.txnp, _key, _value.get_float_value())) {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invoked on %s=%f", _config.c_str(), _value.get_float_value());
      } else {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invocation failed on %s=%f", _config.c_str(), _value.get_float_value());
      }
      break;
    case TS_RECORDDATATYPE_STRING:
      if (TS_SUCCESS == TSHttpTxnConfigStringSet(res.txnp, _key, _value.get_value().c_str(), _value.size())) {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invoked on %s=%s", _config.c_str(), _value.get_value().c_str());
      } else {
        Dbg(pi_dbg_ctl, "OperatorSetConfig::exec() invocation failed on %s=%s", _config.c_str(), _value.get_value().c_str());
      }
      break;
    default:
      TSError("[%s] unknown data type, whut?", PLUGIN_NAME);
      break;
    }
  }
  return true;
}

// OperatorSetStatus
void
OperatorSetStatus::initialize(Parser &p)
{
  Operator::initialize(p);

  _status.set_value(p.get_arg());

  if (nullptr == (_reason = TSHttpHdrReasonLookup(static_cast<TSHttpStatus>(_status.get_int_value())))) {
    TSError("[%s] unknown status %d", PLUGIN_NAME, _status.get_int_value());
    _reason_len = 0;
  } else {
    _reason_len = strlen(_reason);
  }

  require_resources(RSRC_SERVER_RESPONSE_HEADERS);
  require_resources(RSRC_CLIENT_RESPONSE_HEADERS);
  require_resources(RSRC_RESPONSE_STATUS);
}

void
OperatorSetStatus::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_PRE_REMAP_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

bool
OperatorSetStatus::exec(const Resources &res) const
{
  switch (get_hook()) {
  case TS_HTTP_READ_RESPONSE_HDR_HOOK:
  case TS_HTTP_SEND_RESPONSE_HDR_HOOK:
    if (res.bufp && res.hdr_loc) {
      TSHttpHdrStatusSet(res.bufp, res.hdr_loc, static_cast<TSHttpStatus>(_status.get_int_value()));
      if (_reason && _reason_len > 0) {
        TSHttpHdrReasonSet(res.bufp, res.hdr_loc, _reason, _reason_len);
      }
    }
    break;
  default:
    TSHttpTxnStatusSet(res.txnp, static_cast<TSHttpStatus>(_status.get_int_value()));
    break;
  }

  Dbg(pi_dbg_ctl, "OperatorSetStatus::exec() invoked with status=%d", _status.get_int_value());

  return true;
}

// OperatorSetStatusReason
void
OperatorSetStatusReason::initialize(Parser &p)
{
  Operator::initialize(p);

  _reason.set_value(p.get_arg());
  require_resources(RSRC_CLIENT_RESPONSE_HEADERS);
  require_resources(RSRC_SERVER_RESPONSE_HEADERS);
}

void
OperatorSetStatusReason::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
}

bool
OperatorSetStatusReason::exec(const Resources &res) const
{
  if (res.bufp && res.hdr_loc) {
    std::string reason;

    _reason.append_value(reason, res);
    if (reason.size() > 0) {
      Dbg(pi_dbg_ctl, "Setting Status Reason to %s", reason.c_str());
      TSHttpHdrReasonSet(res.bufp, res.hdr_loc, reason.c_str(), reason.size());
    }
  }
  return true;
}

// OperatorSetDestination
void
OperatorSetDestination::initialize(Parser &p)
{
  Operator::initialize(p);

  _url_qual = parse_url_qualifier(p.get_arg());
  _value.set_value(p.get_value());
  require_resources(RSRC_CLIENT_REQUEST_HEADERS);
  require_resources(RSRC_SERVER_REQUEST_HEADERS);
}

bool
OperatorSetDestination::exec(const Resources &res) const
{
  if (res._rri || (res.bufp && res.hdr_loc)) {
    std::string value;

    // Determine which TSMBuffer and TSMLoc to use
    TSMBuffer bufp;
    TSMLoc    url_m_loc;
    if (res._rri && !res.changed_url) {
      bufp      = res._rri->requestBufp;
      url_m_loc = res._rri->requestUrl;
    } else {
      bufp = res.bufp;
      if (TSHttpHdrUrlGet(res.bufp, res.hdr_loc, &url_m_loc) != TS_SUCCESS) {
        Dbg(pi_dbg_ctl, "TSHttpHdrUrlGet was unable to return the url m_loc");
        return true;
      }
    }

    // Never set an empty destination value (I don't think that ever makes sense?)
    switch (_url_qual) {
    case URL_QUAL_HOST:
      _value.append_value(value, res);
      if (value.empty()) {
        Dbg(pi_dbg_ctl, "Would set destination HOST to an empty value, skipping");
      } else {
        const_cast<Resources &>(res).changed_url = true;
        TSUrlHostSet(bufp, url_m_loc, value.c_str(), value.size());
        Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() invoked with HOST: %s", value.c_str());
      }
      break;

    case URL_QUAL_PATH:
      _value.append_value(value, res);
      if (value.empty()) {
        Dbg(pi_dbg_ctl, "Would set destination PATH to an empty value, skipping");
      } else {
        const_cast<Resources &>(res).changed_url = true;
        TSUrlPathSet(bufp, url_m_loc, value.c_str(), value.size());
        Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() invoked with PATH: %s", value.c_str());
      }
      break;

    case URL_QUAL_QUERY:
      _value.append_value(value, res);
      if (value.empty()) {
        Dbg(pi_dbg_ctl, "Would set destination QUERY to an empty value, skipping");
      } else {
        // 1.6.4--Support for preserving QSA in case of set-destination
        if (get_oper_modifiers() & OPER_QSA) {
          int         query_len = 0;
          const char *query     = TSUrlHttpQueryGet(bufp, url_m_loc, &query_len);
          Dbg(pi_dbg_ctl, "QSA mode, append original query string: %.*s", query_len, query);
          // std::string connector = (value.find("?") == std::string::npos)? "?" : "&";
          value.append("&");
          value.append(query, query_len);
        }

        const_cast<Resources &>(res).changed_url = true;
        TSUrlHttpQuerySet(bufp, url_m_loc, value.c_str(), value.size());
        Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() invoked with QUERY: %s", value.c_str());
      }
      break;

    case URL_QUAL_PORT:
      if (_value.get_int_value() <= 0 || _value.get_int_value() > 0xFFFF) {
        Dbg(pi_dbg_ctl, "Would set destination PORT to an invalid range, skipping");
      } else {
        const_cast<Resources &>(res).changed_url = true;
        TSUrlPortSet(bufp, url_m_loc, _value.get_int_value());
        Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() invoked with PORT: %d", _value.get_int_value());
      }
      break;
    case URL_QUAL_URL:
      _value.append_value(value, res);
      if (value.empty()) {
        Dbg(pi_dbg_ctl, "Would set destination URL to an empty value, skipping");
      } else {
        const char *start = value.c_str();
        const char *end   = start + value.size();
        TSMLoc      new_url_loc;
        if (TSUrlCreate(bufp, &new_url_loc) == TS_SUCCESS && TSUrlParse(bufp, new_url_loc, &start, end) == TS_PARSE_DONE &&
            TSHttpHdrUrlSet(bufp, res.hdr_loc, new_url_loc) == TS_SUCCESS) {
          const_cast<Resources &>(res).changed_url = true;
          Dbg(pi_dbg_ctl, "Set destination URL to %s", value.c_str());
        } else {
          Dbg(pi_dbg_ctl, "Failed to set URL %s", value.c_str());
        }
      }
      break;
    case URL_QUAL_SCHEME:
      _value.append_value(value, res);
      if (value.empty()) {
        Dbg(pi_dbg_ctl, "Would set destination SCHEME to an empty value, skipping");
      } else {
        TSUrlSchemeSet(bufp, url_m_loc, value.c_str(), value.length());
        const_cast<Resources &>(res).changed_url = true;
        Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() invoked with SCHEME: %s", value.c_str());
      }
      break;
    default:
      Dbg(pi_dbg_ctl, "Set destination %i has no handler", _url_qual);
      break;
    }
  } else {
    Dbg(pi_dbg_ctl, "OperatorSetDestination::exec() unable to continue due to missing bufp=%p or hdr_loc=%p, rri=%p!", res.bufp,
        res.hdr_loc, res._rri);
  }
  return true;
}

#include <iostream>

// OperatorRMDestination
static std::vector<std::string_view>
_tokenize(swoc::TextView text, char delimiter)
{
  std::vector<std::string_view> tokens;

  while (text) {
    tokens.push_back(text.take_prefix_at(delimiter));
  }

  return tokens;
}

void
OperatorRMDestination::initialize(Parser &p)
{
  Operator::initialize(p);

  _url_qual = parse_url_qualifier(p.get_arg());
  _stop     = p.get_value();

  if (!_stop.empty()) {
    if (get_oper_modifiers() & OPER_INV) {
      _keep = true;
    }
    _stop_list = _tokenize(_stop, ',');
  }

  require_resources(RSRC_CLIENT_REQUEST_HEADERS);
  require_resources(RSRC_SERVER_REQUEST_HEADERS);
}

bool
OperatorRMDestination::exec(const Resources &res) const
{
  if (res._rri || (res.bufp && res.hdr_loc)) {
    std::string value = "";

    // Determine which TSMBuffer and TSMLoc to use
    TSMBuffer bufp;
    TSMLoc    url_m_loc;
    if (res._rri) {
      bufp      = res._rri->requestBufp;
      url_m_loc = res._rri->requestUrl;
    } else {
      bufp = res.bufp;
      if (TSHttpHdrUrlGet(res.bufp, res.hdr_loc, &url_m_loc) != TS_SUCCESS) {
        Dbg(pi_dbg_ctl, "TSHttpHdrUrlGet was unable to return the url m_loc");
        return true;
      }
    }

    // Never set an empty destination value (I don't think that ever makes sense?)
    switch (_url_qual) {
    case URL_QUAL_PATH:
      const_cast<Resources &>(res).changed_url = true;
      TSUrlPathSet(bufp, url_m_loc, value.c_str(), value.size());
      Dbg(pi_dbg_ctl, "OperatorRMDestination::exec() deleting PATH");
      break;
    case URL_QUAL_QUERY:
      if (_stop_list.size() > 0) {
        int         q_len = 0;
        const char *query = TSUrlHttpQueryGet(bufp, url_m_loc, &q_len);

        if (q_len > 0) {
          for (auto &q : _tokenize({query, static_cast<size_t>(q_len)}, '&')) {
            auto eq_pos = q.find('=');
            auto it = std::find(_stop_list.begin(), _stop_list.end(), (eq_pos != std::string_view::npos) ? q.substr(0, eq_pos) : q);

            if (_keep == (it != _stop_list.end())) {
              if (!value.empty()) {
                value.append("&").append(q);
              } else {
                value = q;
              }
            }
          }
        }
        Dbg(pi_dbg_ctl, "OperatorRMDestination::exec() rewrote QUERY to \"%s\"", value.c_str());
      } else {
        Dbg(pi_dbg_ctl, "OperatorRMDestination::exec() deleting QUERY");
      }
      const_cast<Resources &>(res).changed_url = true;
      TSUrlHttpQuerySet(bufp, url_m_loc, value.c_str(), value.size());
      break;
    case URL_QUAL_PORT:
      const_cast<Resources &>(res).changed_url = true;
      TSUrlPortSet(bufp, url_m_loc, 0);
      Dbg(pi_dbg_ctl, "OperatorRMDestination::exec() deleting PORT");
      break;
    default:
      Dbg(pi_dbg_ctl, "RM Destination %i has no handler", _url_qual);
      break;
    }
  } else {
    Dbg(pi_dbg_ctl, "OperatorRMDestination::exec() unable to continue due to missing bufp=%p or hdr_loc=%p, rri=%p!", res.bufp,
        res.hdr_loc, res._rri);
  }
  return true;
}

// OperatorSetRedirect
void
OperatorSetRedirect::initialize(Parser &p)
{
  Operator::initialize(p);

  _status.set_value(p.get_arg());
  _location.set_value(p.get_value());
  auto status = _status.get_int_value();
  if (status < 300 || status > 399 || status == TS_HTTP_STATUS_NOT_MODIFIED) {
    TSError("[%s] unsupported redirect status %d", PLUGIN_NAME, status);
  }

  require_resources(RSRC_SERVER_RESPONSE_HEADERS);
  require_resources(RSRC_CLIENT_RESPONSE_HEADERS);
  require_resources(RSRC_CLIENT_REQUEST_HEADERS);
  require_resources(RSRC_RESPONSE_STATUS);
}

void
OperatorSetRedirect::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

void
EditRedirectResponse(TSHttpTxn txnp, const std::string &location, TSHttpStatus status, TSMBuffer bufp, TSMLoc hdr_loc)
{
  // Set new location.
  TSMLoc             field_loc;
  static std::string header("Location");
  if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(bufp, hdr_loc, header.c_str(), header.size(), &field_loc)) {
    if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(bufp, hdr_loc, field_loc, -1, location.c_str(), location.size())) {
      Dbg(pi_dbg_ctl, "   Adding header %s", header.c_str());
      TSMimeHdrFieldAppend(bufp, hdr_loc, field_loc);
    }
    const char *reason = TSHttpHdrReasonLookup(status);
    size_t      len    = strlen(reason);
    TSHttpHdrReasonSet(bufp, hdr_loc, reason, len);
    TSHandleMLocRelease(bufp, hdr_loc, field_loc);
  }

  // Set the body.
  static std::string msg = "<HTML>\n<HEAD>\n<TITLE>Document Has Moved</TITLE>\n</HEAD>\n"
                           "<BODY BGCOLOR=\"white\" FGCOLOR=\"black\">\n"
                           "<H1>Document Has Moved</H1>\n<HR>\n<FONT FACE=\"Helvetica,Arial\"><B>\n"
                           "Description: The document you requested has moved to a new location."
                           " The new location is \"" +
                           location + "\".\n</B></FONT>\n<HR>\n</BODY>\n";
  TSHttpTxnErrorBodySet(txnp, TSstrdup(msg.c_str()), msg.length(), TSstrdup("text/html"));
}

bool
OperatorSetRedirect::exec(const Resources &res) const
{
  if (res.bufp && res.hdr_loc && res.client_bufp && res.client_hdr_loc) {
    std::string value;

    _location.append_value(value, res);

    bool remap = false;
    if (nullptr != res._rri) {
      remap = true;
      Dbg(pi_dbg_ctl, "OperatorSetRedirect:exec() invoked from remap plugin");
    } else {
      Dbg(pi_dbg_ctl, "OperatorSetRedirect:exec() not invoked from remap plugin");
    }

    TSMBuffer bufp;
    TSMLoc    url_loc;
    if (remap) {
      // Handle when called from remap plugin.
      bufp    = res._rri->requestBufp;
      url_loc = res._rri->requestUrl;
    } else {
      // Handle when not called from remap plugin.
      bufp = res.client_bufp;
      if (TS_SUCCESS != TSHttpHdrUrlGet(res.client_bufp, res.client_hdr_loc, &url_loc)) {
        Dbg(pi_dbg_ctl, "Could not get client URL");
      }
    }

    // Replace %{PATH} to original path
    size_t pos_path = 0;
    if ((pos_path = value.find("%{PATH}")) != std::string::npos) {
      value.erase(pos_path, 7); // erase %{PATH} from the rewritten to url
      int         path_len = 0;
      const char *path     = TSUrlPathGet(bufp, url_loc, &path_len);
      if (path_len > 0) {
        Dbg(pi_dbg_ctl, "Find %%{PATH} in redirect url, replace it with: %.*s", path_len, path);
        value.insert(pos_path, path, path_len);
      }
    }

    // Append the original query string
    int         query_len = 0;
    const char *query     = TSUrlHttpQueryGet(bufp, url_loc, &query_len);

    if ((get_oper_modifiers() & OPER_QSA) && (query_len > 0)) {
      Dbg(pi_dbg_ctl, "QSA mode, append original query string: %.*s", query_len, query);
      std::string connector = (value.find('?') == std::string::npos) ? "?" : "&";
      value.append(connector);
      value.append(query, query_len);
    }

    // Prepare the destination URL for the redirect.
    const char *start = value.c_str();
    const char *end   = value.size() + start;
    if (remap) {
      // Set new location.
      if (TS_PARSE_ERROR == TSUrlParse(bufp, url_loc, &start, end)) {
        Dbg(pi_dbg_ctl, "Could not set Location field value to: %s", value.c_str());
      }
      // Set the new status.
      TSHttpTxnStatusSet(res.txnp, static_cast<TSHttpStatus>(_status.get_int_value()));
      const_cast<Resources &>(res).changed_url = true;
      res._rri->redirect                       = 1;
    } else {
      Dbg(pi_dbg_ctl, "OperatorSetRedirect::exec() hook=%d", int(get_hook()));
      // Set the new status code and reason.
      TSHttpStatus status = static_cast<TSHttpStatus>(_status.get_int_value());
      TSHttpHdrStatusSet(res.bufp, res.hdr_loc, status);
      EditRedirectResponse(res.txnp, value, status, res.bufp, res.hdr_loc);
    }
    Dbg(pi_dbg_ctl, "OperatorSetRedirect::exec() invoked with destination=%s and status code=%d", value.c_str(),
        _status.get_int_value());
  }
  return true;
}

// OperatorSetTimeoutOut
void
OperatorSetTimeoutOut::initialize(Parser &p)
{
  Operator::initialize(p);

  if (p.get_arg() == "active") {
    _type = TO_OUT_ACTIVE;
  } else if (p.get_arg() == "inactive") {
    _type = TO_OUT_INACTIVE;
  } else if (p.get_arg() == "connect") {
    _type = TO_OUT_CONNECT;
  } else if (p.get_arg() == "dns") {
    _type = TO_OUT_DNS;
  } else {
    _type = TO_OUT_UNDEFINED;
    TSError("[%s] unsupported timeout qualifier: %s", PLUGIN_NAME, p.get_arg().c_str());
  }

  _timeout.set_value(p.get_value());
}

bool
OperatorSetTimeoutOut::exec(const Resources &res) const
{
  switch (_type) {
  case TO_OUT_ACTIVE:
    Dbg(pi_dbg_ctl, "OperatorSetTimeoutOut::exec(active, %d)", _timeout.get_int_value());
    TSHttpTxnActiveTimeoutSet(res.txnp, _timeout.get_int_value());
    break;

  case TO_OUT_INACTIVE:
    Dbg(pi_dbg_ctl, "OperatorSetTimeoutOut::exec(inactive, %d)", _timeout.get_int_value());
    TSHttpTxnNoActivityTimeoutSet(res.txnp, _timeout.get_int_value());
    break;

  case TO_OUT_CONNECT:
    Dbg(pi_dbg_ctl, "OperatorSetTimeoutOut::exec(connect, %d)", _timeout.get_int_value());
    TSHttpTxnConnectTimeoutSet(res.txnp, _timeout.get_int_value());
    break;

  case TO_OUT_DNS:
    Dbg(pi_dbg_ctl, "OperatorSetTimeoutOut::exec(dns, %d)", _timeout.get_int_value());
    TSHttpTxnDNSTimeoutSet(res.txnp, _timeout.get_int_value());
    break;
  default:
    TSError("[%s] unsupported timeout", PLUGIN_NAME);
    break;
  }
  return true;
}

// OperatorSkipRemap
// Deprecated: Remove for v10.0.0
void
OperatorSkipRemap::initialize(Parser &p)
{
  Operator::initialize(p);

  if (p.get_arg() == "1" || p.get_arg() == "true" || p.get_arg() == "TRUE") {
    _skip_remap = true;
  }
}

bool
OperatorSkipRemap::exec(const Resources &res) const
{
  Dbg(pi_dbg_ctl, "OperatorSkipRemap::exec() skipping remap: %s", _skip_remap ? "True" : "False");
  TSHttpTxnCntlSet(res.txnp, TS_HTTP_CNTL_SKIP_REMAPPING, _skip_remap);
  return true;
}

// OperatorRMHeader
bool
OperatorRMHeader::exec(const Resources &res) const
{
  TSMLoc field_loc, tmp;

  if (res.bufp && res.hdr_loc) {
    Dbg(pi_dbg_ctl, "OperatorRMHeader::exec() invoked on %s", _header.c_str());
    field_loc = TSMimeHdrFieldFind(res.bufp, res.hdr_loc, _header.c_str(), _header.size());
    while (field_loc) {
      Dbg(pi_dbg_ctl, "   Deleting header %s", _header.c_str());
      tmp = TSMimeHdrFieldNextDup(res.bufp, res.hdr_loc, field_loc);
      TSMimeHdrFieldDestroy(res.bufp, res.hdr_loc, field_loc);
      TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
      field_loc = tmp;
    }
  }
  return true;
}

// OperatorAddHeader
void
OperatorAddHeader::initialize(Parser &p)
{
  OperatorHeaders::initialize(p);

  _value.set_value(p.get_value());
}

bool
OperatorAddHeader::exec(const Resources &res) const
{
  std::string value;

  _value.append_value(value, res);

  // Never set an empty header (I don't think that ever makes sense?)
  if (value.empty()) {
    Dbg(pi_dbg_ctl, "Would set header %s to an empty value, skipping", _header.c_str());
    return true;
  }

  if (res.bufp && res.hdr_loc) {
    Dbg(pi_dbg_ctl, "OperatorAddHeader::exec() invoked on %s: %s", _header.c_str(), value.c_str());
    TSMLoc field_loc;

    if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(res.bufp, res.hdr_loc, _header.c_str(), _header.size(), &field_loc)) {
      if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, value.c_str(), value.size())) {
        Dbg(pi_dbg_ctl, "   Adding header %s", _header.c_str());
        TSMimeHdrFieldAppend(res.bufp, res.hdr_loc, field_loc);
      }
      TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
    }
  }
  return true;
}

// OperatorSetHeader
void
OperatorSetHeader::initialize(Parser &p)
{
  OperatorHeaders::initialize(p);

  _value.set_value(p.get_value());
}

bool
OperatorSetHeader::exec(const Resources &res) const
{
  std::string value;

  _value.append_value(value, res);

  // Never set an empty header (I don't think that ever makes sense?)
  if (value.empty()) {
    Dbg(pi_dbg_ctl, "Would set header %s to an empty value, skipping", _header.c_str());
    return true;
  }

  if (res.bufp && res.hdr_loc) {
    TSMLoc field_loc = TSMimeHdrFieldFind(res.bufp, res.hdr_loc, _header_wks ? _header_wks : _header.c_str(), _header.size());

    Dbg(pi_dbg_ctl, "OperatorSetHeader::exec() invoked on %s: %s", _header.c_str(), value.c_str());

    if (!field_loc) {
      // No existing header, so create one
      if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(res.bufp, res.hdr_loc, _header.c_str(), _header.size(), &field_loc)) {
        if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, value.c_str(), value.size())) {
          Dbg(pi_dbg_ctl, "   Adding header %s", _header.c_str());
          TSMimeHdrFieldAppend(res.bufp, res.hdr_loc, field_loc);
        }
        TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
      }
    } else {
      TSMLoc tmp   = nullptr;
      bool   first = true;

      while (field_loc) {
        tmp = TSMimeHdrFieldNextDup(res.bufp, res.hdr_loc, field_loc);
        if (first) {
          first = false;
          if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, value.c_str(), value.size())) {
            Dbg(pi_dbg_ctl, "   Overwriting header %s", _header.c_str());
          }
        } else {
          TSMimeHdrFieldDestroy(res.bufp, res.hdr_loc, field_loc);
        }
        TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
        field_loc = tmp;
      }
    }
  }
  return true;
}

// OperatorSetBody
void
OperatorSetBody::initialize(Parser &p)
{
  Operator::initialize(p);
  // we want the arg since body only takes one value
  _value.set_value(p.get_arg());
}

void
OperatorSetBody::initialize_hooks()
{
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
}

bool
OperatorSetBody::exec(const Resources &res) const
{
  std::string value;

  _value.append_value(value, res);
  char *msg = TSstrdup(_value.get_value().c_str());
  TSHttpTxnErrorBodySet(res.txnp, msg, _value.size(), nullptr);
  return true;
}

// OperatorCounter
void
OperatorCounter::initialize(Parser &p)
{
  Operator::initialize(p);

  _counter_name = p.get_arg();

  // Sanity
  if (_counter_name.length() == 0) {
    TSError("[%s] counter name is empty", PLUGIN_NAME);
    return;
  }

  // Check if counter already created by another rule
  if (TSStatFindName(_counter_name.c_str(), &_counter) == TS_ERROR) {
    _counter = TSStatCreate(_counter_name.c_str(), TS_RECORDDATATYPE_INT, TS_STAT_NON_PERSISTENT, TS_STAT_SYNC_COUNT);
    if (_counter == TS_ERROR) {
      TSError("[%s] TSStatCreate() failed. Can't create counter: %s", PLUGIN_NAME, _counter_name.c_str());
      return;
    }
    Dbg(pi_dbg_ctl, "OperatorCounter::initialize(%s) created counter with id: %d", _counter_name.c_str(), _counter);
  } else {
    Dbg(pi_dbg_ctl, "OperatorCounter::initialize(%s) reusing id: %d", _counter_name.c_str(), _counter);
  }
}

bool
OperatorCounter::exec(const Resources & /* ATS_UNUSED res */) const
{
  // Sanity
  if (_counter == TS_ERROR) {
    return true;
  }

  Dbg(pi_dbg_ctl, "OperatorCounter::exec() invoked on %s", _counter_name.c_str());
  TSStatIntIncrement(_counter, 1);
  return true;
}

// OperatorRMCookie
bool
OperatorRMCookie::exec(const Resources &res) const
{
  if (res.bufp && res.hdr_loc) {
    Dbg(pi_dbg_ctl, "OperatorRMCookie::exec() invoked on cookie %s", _cookie.c_str());
    TSMLoc field_loc;

    // Find Cookie
    field_loc = TSMimeHdrFieldFind(res.bufp, res.hdr_loc, TS_MIME_FIELD_COOKIE, TS_MIME_LEN_COOKIE);
    if (nullptr == field_loc) {
      Dbg(pi_dbg_ctl, "OperatorRMCookie::exec, no cookie");
      return true;
    }

    int         cookies_len = 0;
    const char *cookies     = TSMimeHdrFieldValueStringGet(res.bufp, res.hdr_loc, field_loc, -1, &cookies_len);
    std::string updated_cookie;
    if (CookieHelper::cookieModifyHelper(cookies, cookies_len, updated_cookie, CookieHelper::COOKIE_OP_DEL, _cookie)) {
      if (updated_cookie.empty()) {
        if (TS_SUCCESS == TSMimeHdrFieldDestroy(res.bufp, res.hdr_loc, field_loc)) {
          Dbg(pi_dbg_ctl, "OperatorRMCookie::exec, empty cookie deleted");
        }
      } else if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, updated_cookie.c_str(),
                                                            updated_cookie.size())) {
        Dbg(pi_dbg_ctl, "OperatorRMCookie::exec, updated_cookie = [%s]", updated_cookie.c_str());
      }
    }
    TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
  }
  return true;
}

// OperatorAddCookie
void
OperatorAddCookie::initialize(Parser &p)
{
  OperatorCookies::initialize(p);
  _value.set_value(p.get_value());
}

bool
OperatorAddCookie::exec(const Resources &res) const
{
  std::string value;

  _value.append_value(value, res);

  if (res.bufp && res.hdr_loc) {
    Dbg(pi_dbg_ctl, "OperatorAddCookie::exec() invoked on cookie %s", _cookie.c_str());
    TSMLoc field_loc;

    // Find Cookie
    field_loc = TSMimeHdrFieldFind(res.bufp, res.hdr_loc, TS_MIME_FIELD_COOKIE, TS_MIME_LEN_COOKIE);
    if (nullptr == field_loc) {
      Dbg(pi_dbg_ctl, "OperatorAddCookie::exec, no cookie");
      if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(res.bufp, res.hdr_loc, TS_MIME_FIELD_COOKIE, TS_MIME_LEN_COOKIE, &field_loc)) {
        value = _cookie + '=' + value;
        if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, value.c_str(), value.size())) {
          Dbg(pi_dbg_ctl, "Adding cookie %s", _cookie.c_str());
          TSMimeHdrFieldAppend(res.bufp, res.hdr_loc, field_loc);
        }
        TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
      }
      return true;
    }

    int         cookies_len = 0;
    const char *cookies     = TSMimeHdrFieldValueStringGet(res.bufp, res.hdr_loc, field_loc, -1, &cookies_len);
    std::string updated_cookie;
    if (CookieHelper::cookieModifyHelper(cookies, cookies_len, updated_cookie, CookieHelper::COOKIE_OP_ADD, _cookie, value) &&
        TS_SUCCESS ==
          TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, updated_cookie.c_str(), updated_cookie.size())) {
      Dbg(pi_dbg_ctl, "OperatorAddCookie::exec, updated_cookie = [%s]", updated_cookie.c_str());
    }
  }
  return true;
}

// OperatorSetCookie
void
OperatorSetCookie::initialize(Parser &p)
{
  OperatorCookies::initialize(p);
  _value.set_value(p.get_value());
}

bool
OperatorSetCookie::exec(const Resources &res) const
{
  std::string value;

  _value.append_value(value, res);

  if (res.bufp && res.hdr_loc) {
    Dbg(pi_dbg_ctl, "OperatorSetCookie::exec() invoked on cookie %s", _cookie.c_str());
    TSMLoc field_loc;

    // Find Cookie
    field_loc = TSMimeHdrFieldFind(res.bufp, res.hdr_loc, TS_MIME_FIELD_COOKIE, TS_MIME_LEN_COOKIE);
    if (nullptr == field_loc) {
      Dbg(pi_dbg_ctl, "OperatorSetCookie::exec, no cookie");
      if (TS_SUCCESS == TSMimeHdrFieldCreateNamed(res.bufp, res.hdr_loc, TS_MIME_FIELD_COOKIE, TS_MIME_LEN_COOKIE, &field_loc)) {
        value = _cookie + "=" + value;
        if (TS_SUCCESS == TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, value.c_str(), value.size())) {
          Dbg(pi_dbg_ctl, "Adding cookie %s", _cookie.c_str());
          TSMimeHdrFieldAppend(res.bufp, res.hdr_loc, field_loc);
        }
        TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
      }
      return true;
    }

    int         cookies_len = 0;
    const char *cookies     = TSMimeHdrFieldValueStringGet(res.bufp, res.hdr_loc, field_loc, -1, &cookies_len);
    std::string updated_cookie;
    if (CookieHelper::cookieModifyHelper(cookies, cookies_len, updated_cookie, CookieHelper::COOKIE_OP_SET, _cookie, value) &&
        TS_SUCCESS ==
          TSMimeHdrFieldValueStringSet(res.bufp, res.hdr_loc, field_loc, -1, updated_cookie.c_str(), updated_cookie.size())) {
      Dbg(pi_dbg_ctl, "OperatorSetCookie::exec, updated_cookie = [%s]", updated_cookie.c_str());
    }
    TSHandleMLocRelease(res.bufp, res.hdr_loc, field_loc);
  }
  return true;
}

bool
CookieHelper::cookieModifyHelper(const char *cookies, const size_t cookies_len, std::string &updated_cookies,
                                 const CookieHelper::CookieOp cookie_op, const std::string &cookie_key,
                                 const std::string &cookie_value)
{
  if (0 == cookie_key.size()) {
    Dbg(pi_dbg_ctl, "CookieHelper::cookieModifyHelper, empty cookie_key");
    return false;
  }

  for (size_t idx = 0; idx < cookies_len;) {
    // advance any leading spaces
    for (; idx < cookies_len && std::isspace(cookies[idx]); idx++) {
      ;
    }
    if (0 == strncmp(cookies + idx, cookie_key.c_str(), cookie_key.size())) {
      size_t key_start_idx = idx;
      // advance to past the name and any subsequent spaces
      for (idx += cookie_key.size(); idx < cookies_len && std::isspace(cookies[idx]); idx++) {
        ;
      }
      if (idx < cookies_len && cookies[idx++] == '=') {
        // cookie_key is found, then we don't need to add it.
        if (CookieHelper::COOKIE_OP_ADD == cookie_op) {
          return false;
        }
        for (; idx < cookies_len && std::isspace(cookies[idx]); idx++) {
          ;
        }
        size_t value_start_idx = idx;
        for (; idx < cookies_len && cookies[idx] != ';'; idx++) {
          ;
        }
        // If we have not reached the end and there is a space after the
        // semi-colon, advance one char
        if (idx + 1 < cookies_len && std::isspace(cookies[idx + 1])) {
          idx++;
        }
        // cookie value is found
        size_t value_end_idx = idx;
        if (CookieHelper::COOKIE_OP_SET == cookie_op) {
          updated_cookies.append(cookies, value_start_idx);
          updated_cookies.append(cookie_value);
          updated_cookies.append(cookies + value_end_idx, cookies_len - value_end_idx);
          return true;
        }

        if (CookieHelper::COOKIE_OP_DEL == cookie_op) {
          // +1 to skip the semi-colon after the cookie_value
          updated_cookies.append(cookies, key_start_idx);
          if (value_end_idx < cookies_len) {
            updated_cookies.append(cookies + value_end_idx + 1, cookies_len - value_end_idx - 1);
          }
          // if the cookie to delete is the last pair,
          // the semi-colon before this pair needs to be deleted
          // this handles the case "c = b; key=value", the expected result is "c = b"
          size_t last_semi_colon = updated_cookies.find_last_of(';');
          if (last_semi_colon != std::string::npos) {
            size_t last_equal = updated_cookies.find_last_of('=');
            if (last_equal != std::string::npos) {
              if (last_equal < last_semi_colon) {
                // remove the last semi colon and subsequent chars
                updated_cookies = updated_cookies.substr(0, last_semi_colon);
              }
            } else {
              // if there is no equal left in cookie, valid cookie value doesn't exist
              updated_cookies = "";
            }
          }
          return true;
        }
      }
    }
    // find the next cookie pair followed by semi-colon
    while (idx < cookies_len && cookies[idx++] != ';') {
      ;
    }
  }

  if (CookieHelper::COOKIE_OP_ADD == cookie_op || CookieHelper::COOKIE_OP_SET == cookie_op) {
    if (0 == cookies_len) {
      updated_cookies = cookie_key + '=' + cookie_value;
    } else {
      updated_cookies = std::string(cookies, cookies_len) + ';' + cookie_key + '=' + cookie_value;
    }
    return true;
  }
  return false;
}

// OperatorSetConnDSCP
void
OperatorSetConnDSCP::initialize(Parser &p)
{
  Operator::initialize(p);

  _ds_value.set_value(p.get_arg());
}

void
OperatorSetConnDSCP::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

bool
OperatorSetConnDSCP::exec(const Resources &res) const
{
  if (res.txnp) {
    TSHttpTxnClientPacketDscpSet(res.txnp, _ds_value.get_int_value());
    Dbg(pi_dbg_ctl, "   Setting DSCP to %d", _ds_value.get_int_value());
  }
  return true;
}

// OperatorSetConnMark
void
OperatorSetConnMark::initialize(Parser &p)
{
  Operator::initialize(p);

  _ds_value.set_value(p.get_arg());
}

void
OperatorSetConnMark::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

bool
OperatorSetConnMark::exec(const Resources &res) const
{
  if (res.txnp) {
    TSHttpTxnClientPacketMarkSet(res.txnp, _ds_value.get_int_value());
    Dbg(pi_dbg_ctl, "   Setting MARK to %d", _ds_value.get_int_value());
  }
  return true;
}

// OperatorSetDebug
// Deprecated: Remove for v10.0.0
void
OperatorSetDebug::initialize(Parser &p)
{
  Operator::initialize(p);
}

void
OperatorSetDebug::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

bool
OperatorSetDebug::exec(const Resources &res) const
{
  TSHttpTxnCntlSet(res.txnp, TS_HTTP_CNTL_TXN_DEBUG, true);
  return true;
}

void
OperatorSetHttpCntl::initialize(Parser &p)
{
  Operator::initialize(p);
  _cntl_qual = parse_http_cntl_qualifier(p.get_arg());

  std::string flag = p.get_value(); // Make a copy of the value

  std::transform(flag.begin(), flag.end(), flag.begin(), ::tolower);

  if (flag == "1" || flag == "true" || flag == "on" || flag == "enable") {
    _flag = true;
  }
}

void
OperatorSetHttpCntl::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
}

// This is only for the debug statement, and must be in sync with TSHttpCntlType in apidefs.h.in
static const char *const HttpCntls[] = {
  "LOGGING", "INTERCEPT_RETRY", "RESP_CACHEABLE", "REQ_CACHEABLE", "SERVER_NO_STORE", "TXN_DEBUG", "SKIP_REMAP",
};

bool
OperatorSetHttpCntl::exec(const Resources &res) const
{
  if (_flag) {
    TSHttpTxnCntlSet(res.txnp, _cntl_qual, true);
    Dbg(pi_dbg_ctl, "   Turning ON %s for transaction", HttpCntls[static_cast<size_t>(_cntl_qual)]);
  } else {
    TSHttpTxnCntlSet(res.txnp, _cntl_qual, false);
    Dbg(pi_dbg_ctl, "   Turning OFF %s for transaction", HttpCntls[static_cast<size_t>(_cntl_qual)]);
  }
  return true;
}

void
OperatorSetPluginCntl::initialize(Parser &p)
{
  Operator::initialize(p);
  const std::string &name  = p.get_arg();
  const std::string &value = p.get_value();

  if (name == "TIMEZONE") {
    _name = PluginCtrl::TIMEZONE;
    if (value == "LOCAL") {
      _value = TIMEZONE_LOCAL;
    } else if (value == "GMT") {
      _value = TIMEZONE_GMT;
    } else {
      TSError("[%s] Unknown value for TIMZEONE control: %s", PLUGIN_NAME, value.c_str());
    }
  } else if (name == "INBOUND_IP_SOURCE") {
    _name = PluginCtrl::INBOUND_IP_SOURCE;
    if (value == "PEER") {
      _value = IP_SRC_PEER;
    } else if (value == "PROXY") {
      _value = IP_SRC_PROXY;
    } else {
      TSError("[%s] Unknown value for INBOUND_IP_SOURCE control: %s", PLUGIN_NAME, value.c_str());
    }
  }
}

// This operator should be allowed everywhere
void
OperatorSetPluginCntl::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
  add_allowed_hook(TS_HTTP_PRE_REMAP_HOOK);
  add_allowed_hook(TS_HTTP_SEND_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_TXN_CLOSE_HOOK);
  add_allowed_hook(TS_HTTP_TXN_START_HOOK);
}

bool
OperatorSetPluginCntl::exec(const Resources &res) const
{
  PrivateSlotData private_data;
  private_data.raw = reinterpret_cast<uint64_t>(TSUserArgGet(res.txnp, _txn_private_slot));

  switch (_name) {
  case PluginCtrl::TIMEZONE:
    private_data.timezone = _value;
    break;
  case PluginCtrl::INBOUND_IP_SOURCE:
    private_data.ip_source = _value;
    break;
  }

  Dbg(pi_dbg_ctl, "   Setting plugin control %d to %d", static_cast<int>(_name), _value);
  TSUserArgSet(res.txnp, _txn_private_slot, reinterpret_cast<void *>(private_data.raw));

  return true;
}

void
OperatorRunPlugin::initialize(Parser &p)
{
  Operator::initialize(p);

  auto plugin_name = p.get_arg();
  auto plugin_args = p.get_value();

  if (plugin_name.empty()) {
    TSError("[%s] missing plugin name", PLUGIN_NAME);
    return;
  }

  std::vector<std::string> tokens;
  std::istringstream       iss(plugin_args);
  std::string              token;

  while (iss >> std::quoted(token)) {
    tokens.push_back(token);
  }

  // Create argc and argv
  int    argc = tokens.size() + 2;
  char **argv = new char *[argc];

  argv[0] = p.from_url();
  argv[1] = p.to_url();

  for (int i = 0; i < argc; ++i) {
    argv[i + 2] = const_cast<char *>(tokens[i].c_str());
  }

  std::string error;

  // We have to escalate access while loading these plugins, just as done when loading remap.config
  {
    uint32_t elevate_access = 0;

    elevate_access = RecGetRecordInt("proxy.config.plugin.load_elevated").value_or(0);
    ElevateAccess access(elevate_access ? ElevateAccess::FILE_PRIVILEGE : 0);

    _plugin = plugin_factory.getRemapPlugin(swoc::file::path(plugin_name), argc, const_cast<char **>(argv), error,
                                            isPluginDynamicReloadEnabled());
  } // done elevating access

  delete[] argv;

  if (!_plugin) {
    TSError("[%s] Unable to load plugin '%s': %s", PLUGIN_NAME, plugin_name.c_str(), error.c_str());
  }
}

void
OperatorRunPlugin::initialize_hooks()
{
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);

  require_resources(RSRC_CLIENT_REQUEST_HEADERS); // Need this for the txnp
}

bool
OperatorRunPlugin::exec(const Resources &res) const
{
  TSReleaseAssert(_plugin != nullptr);

  if (res._rri && res.txnp) {
    _plugin->doRemap(res.txnp, res._rri);
  }
  return true;
}

// OperatorSetBody
void
OperatorSetBodyFrom::initialize(Parser &p)
{
  Operator::initialize(p);
  // we want the arg since body only takes one value
  _value.set_value(p.get_arg());
  require_resources(RSRC_SERVER_RESPONSE_HEADERS);
  require_resources(RSRC_RESPONSE_STATUS);
}

void
OperatorSetBodyFrom::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
}

bool
OperatorSetBodyFrom::exec(const Resources &res) const
{
  if (TSHttpTxnIsInternal(res.txnp)) {
    // If this is triggered by an internal transaction, a infinte loop may occur
    // It should only be triggered by the original transaction sent by the client
    Dbg(pi_dbg_ctl, "OperatorSetBodyFrom triggered by an internal transaction");
    return true;
  }

  char req_buf[MAX_SIZE];
  int  req_buf_size = 0;
  if (createRequestString(_value.get_value(), req_buf, &req_buf_size) == TS_SUCCESS) {
    TSCont fetchCont = TSContCreate(handleFetchEvents, TSMutexCreate());
    TSContDataSet(fetchCont, static_cast<void *>(res.txnp));

    TSHttpTxnHookAdd(res.txnp, TS_HTTP_TXN_CLOSE_HOOK, fetchCont);

    TSFetchEvent event_ids;
    event_ids.success_event_id = TS_EVENT_FETCHSM_SUCCESS;
    event_ids.failure_event_id = TS_EVENT_FETCHSM_FAILURE;
    event_ids.timeout_event_id = TS_EVENT_FETCHSM_TIMEOUT;

    struct sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = LOCAL_IP_ADDRESS;
    addr.sin_port        = LOCAL_PORT;
    TSFetchUrl(static_cast<const char *>(req_buf), req_buf_size, reinterpret_cast<struct sockaddr const *>(&addr), fetchCont,
               AFTER_BODY, event_ids);

    // Forces original status code in event TSHttpTxnErrorBodySet changed
    // the code or another condition was set conflicting with this one.
    // Set here because res is the only structure that contains the original status code.
    TSHttpTxnStatusSet(res.txnp, res.resp_status);
  } else {
    TSError(PLUGIN_NAME, "OperatorSetBodyFrom:exec:: Could not create request");
    return true;
  }
  return false;
}

void
OperatorSetStateFlag::initialize(Parser &p)
{
  Operator::initialize(p);

  _flag_ix = strtol(p.get_arg().c_str(), nullptr, 10);

  if (_flag_ix < 0 || _flag_ix >= NUM_STATE_FLAGS) {
    TSError("[%s] state flag with index %d is out of range", PLUGIN_NAME, _flag_ix);
    return;
  }

  std::string flag = p.get_value(); // Make a copy of the value

  std::transform(flag.begin(), flag.end(), flag.begin(), ::tolower);

  if (flag == "1" || flag == "true" || flag == "on" || flag == "enable") {
    _mask = 1ULL << _flag_ix;
    _flag = true;
  } else {
    _mask = ~(1ULL << _flag_ix);
    _flag = false;
  }
}

// This operator should be allowed everywhere
void
OperatorSetStateFlag::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
  add_allowed_hook(TS_HTTP_PRE_REMAP_HOOK);
  add_allowed_hook(TS_HTTP_SEND_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_TXN_CLOSE_HOOK);
  add_allowed_hook(TS_HTTP_TXN_START_HOOK);
}

bool
OperatorSetStateFlag::exec(const Resources &res) const
{
  if (!res.txnp) {
    TSError("[%s] OperatorSetStateFlag() failed. Transaction is null", PLUGIN_NAME);
    return false;
  }

  Dbg(pi_dbg_ctl, "   Setting state flag %d to %d", _flag_ix, _flag);

  auto data = reinterpret_cast<uint64_t>(TSUserArgGet(res.txnp, _txn_slot));

  TSUserArgSet(res.txnp, _txn_slot, reinterpret_cast<void *>(_flag ? data | _mask : data & _mask));

  return true;
}

void
OperatorSetStateInt8::initialize(Parser &p)
{
  Operator::initialize(p);

  _byte_ix = strtol(p.get_arg().c_str(), nullptr, 10);

  if (_byte_ix < 0 || _byte_ix >= NUM_STATE_INT8S) {
    TSError("[%s] state int8 with index %d is out of range", PLUGIN_NAME, _byte_ix);
    return;
  }

  _value.set_value(p.get_value());
  if (!_value.has_conds()) {
    int v = _value.get_int_value();

    if (v < 0 || v > 255) {
      TSError("[%s] state int8 value %d is out of range", PLUGIN_NAME, v);
      return;
    }
  }
}

// This operator should be allowed everywhere
void
OperatorSetStateInt8::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
  add_allowed_hook(TS_HTTP_PRE_REMAP_HOOK);
  add_allowed_hook(TS_HTTP_SEND_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_TXN_CLOSE_HOOK);
  add_allowed_hook(TS_HTTP_TXN_START_HOOK);
}

bool
OperatorSetStateInt8::exec(const Resources &res) const
{
  if (!res.txnp) {
    TSError("[%s] OperatorSetStateInt8() failed. Transaction is null", PLUGIN_NAME);
    return false;
  }

  auto ptr = reinterpret_cast<uint64_t>(TSUserArgGet(res.txnp, _txn_slot));
  int  val = 0;

  if (_value.has_conds()) { // If there are conditions, we need to evaluate them, which gives us a string
    std::string v;

    _value.append_value(v, res);
    val = strtol(v.c_str(), nullptr, 10);
    if (val < 0 || val > 255) {
      TSWarning("[%s] state int8 value %d is out of range", PLUGIN_NAME, val);
      return false;
    }
  } else {
    // These values have already been checked at load time
    val = _value.get_int_value();
  }

  Dbg(pi_dbg_ctl, "   Setting state int8 %d to %d", _byte_ix, val);
  ptr &= ~STATE_INT8_MASKS[_byte_ix]; // Clear any old value
  ptr |= (static_cast<uint64_t>(val) << (NUM_STATE_FLAGS + _byte_ix * 8));
  TSUserArgSet(res.txnp, _txn_slot, reinterpret_cast<void *>(ptr));

  return true;
}

void
OperatorSetStateInt16::initialize(Parser &p)
{
  Operator::initialize(p);

  int ix = strtol(p.get_arg().c_str(), nullptr, 10);

  if (ix != 0) {
    TSError("[%s] state int16 with index %d is out of range", PLUGIN_NAME, ix);
    return;
  }

  _value.set_value(p.get_value());
  if (!_value.has_conds()) {
    int v = _value.get_int_value();

    if (v < 0 || v > 65535) {
      TSError("[%s] state int16 value %d is out of range", PLUGIN_NAME, v);
      return;
    }
  }
}

// This operator should be allowed everywhere
void
OperatorSetStateInt16::initialize_hooks()
{
  add_allowed_hook(TS_HTTP_READ_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_READ_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_HTTP_SEND_RESPONSE_HDR_HOOK);
  add_allowed_hook(TS_REMAP_PSEUDO_HOOK);
  add_allowed_hook(TS_HTTP_PRE_REMAP_HOOK);
  add_allowed_hook(TS_HTTP_SEND_REQUEST_HDR_HOOK);
  add_allowed_hook(TS_HTTP_TXN_CLOSE_HOOK);
  add_allowed_hook(TS_HTTP_TXN_START_HOOK);
}

bool
OperatorSetStateInt16::exec(const Resources &res) const
{
  if (!res.txnp) {
    TSError("[%s] OperatorSetStateInt16() failed. Transaction is null", PLUGIN_NAME);
    return false;
  }

  auto ptr = reinterpret_cast<uint64_t>(TSUserArgGet(res.txnp, _txn_slot));
  int  val = 0;

  if (_value.has_conds()) { // If there are conditions, we need to evaluate them, which gives us a string
    std::string v;

    _value.append_value(v, res);
    val = strtol(v.c_str(), nullptr, 10);
    if (val < 0 || val > 65535) {
      TSWarning("[%s] state int8 value %d is out of range", PLUGIN_NAME, val);
      return false;
    }
  } else {
    // These values have already been checked at load time
    val = _value.get_int_value();
  }

  Dbg(pi_dbg_ctl, "   Setting state int16 to %d", val);
  ptr &= ~STATE_INT16_MASK; // Clear any old value
  ptr |= (static_cast<uint64_t>(val) << 48);
  TSUserArgSet(res.txnp, _txn_slot, reinterpret_cast<void *>(ptr));

  return true;
}
