// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Thread-safe (provides internal synchronization)

#ifndef STORAGE_LEVELDB_DB_TABLE_CACHE_H_
#define STORAGE_LEVELDB_DB_TABLE_CACHE_H_

#include <string>
#include <stdint.h>
#include "db/dbformat.h"
#include "leveldb/cache.h"
#include "leveldb/table.h"
#include "port/port.h"
#include "util/cache2.h"

namespace leveldb {

class Env;

class TableCache {
 public:
  TableCache(const std::string& dbname, const Options* options, Cache * file_cache,
             DoubleCache & doublecache);
  ~TableCache();

  // Return an iterator for the specified file number (the corresponding
  // file length must be exactly "file_size" bytes).  If "tableptr" is
  // non-NULL, also sets "*tableptr" to point to the Table object
  // underlying the returned iterator, or NULL if no Table object underlies
  // the returned iterator.  The returned "*tableptr" object is owned by
  // the cache and should not be deleted, and is valid for as long as the
  // returned iterator is live.
  Iterator* NewIterator(const ReadOptions& options,
                        uint64_t file_number,
                        uint64_t file_size,
                        int level,
                        Table** tableptr = NULL);

  // If a seek to internal key "k" in specified file finds an entry,
  // call (*handle_result)(arg, found_key, found_value).
  Status Get(const ReadOptions& options,
             uint64_t file_number,
             uint64_t file_size,
             int level,
             const Slice& k,
             void* arg,
             bool (*handle_result)(void*, const Slice&, const Slice&));

  // Evict any entry for the specified file number
  void Evict(uint64_t file_number, bool is_overlapped);

  // Riak specific:  return table statistic ONLY if table in cache, otherwise zero
  uint64_t GetStatisticValue(uint64_t file_number, unsigned Index);


  // access for testing tools, not for public access
  Status TEST_FindTable(uint64_t file_number, uint64_t file_size, int level, Cache::Handle** handle)
  {return( FindTable(file_number, file_size, level, handle));};

  Cache* TEST_GetInternalCache() {return(cache_);};

  void Release(Cache::Handle * handle) {cache_->Release(handle);};

 private:
  Env* const env_;
  const std::string dbname_;
  const Options* options_;
  Cache * cache_;
  DoubleCache & doublecache_;

  Status FindTable(uint64_t file_number, uint64_t file_size, int level, Cache::Handle**, bool is_compaction=false);
};


struct TableAndFile {
  RandomAccessFile* file;
  Table* table;
  DoubleCache * doublecache;

   TableAndFile()
   : file(NULL), table(NULL), doublecache(NULL) {};
};


}  // namespace leveldb

#endif  // STORAGE_LEVELDB_DB_TABLE_CACHE_H_
