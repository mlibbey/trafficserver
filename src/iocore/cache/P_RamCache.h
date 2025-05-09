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

#pragma once

// Generic Ram Cache interface

#include "iocore/eventsystem/IOBuffer.h"
#include "tscore/CryptoHash.h"

class StripeSM;

class RamCache
{
public:
  // returns 1 on found/stored, 0 on not found/stored, if provided auxkey1 and auxkey2 must match
  virtual int     get(CryptoHash *key, Ptr<IOBufferData> *ret_data, uint64_t auxkey = 0)                         = 0;
  virtual int     put(CryptoHash *key, IOBufferData *data, uint32_t len, bool copy = false, uint64_t auxkey = 0) = 0;
  virtual int     fixup(const CryptoHash *key, uint64_t old_auxkey, uint64_t new_auxkey)                         = 0;
  virtual int64_t size() const                                                                                   = 0;

  virtual void init(int64_t max_bytes, StripeSM *stripe) = 0;
  virtual ~RamCache(){};
};

RamCache *new_RamCacheLRU();
RamCache *new_RamCacheCLFUS();
