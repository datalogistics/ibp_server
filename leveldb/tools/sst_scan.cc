#include <stdlib.h>
#include <libgen.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "db/filename.h"
#include "leveldb/env.h"
#include "leveldb/db.h"
#include "leveldb/cache.h"
#include "leveldb/filter_policy.h"
#include "leveldb/slice.h"
#include "db/table_cache.h"
#include "db/version_edit.h"
#include "table/format.h"
#include "table/block.h"
#include "table/filter_block.h"
#include "util/cache2.h"

//#include "util/logging.h"
//#include "db/log_reader.h"

void command_help();

int
main(
    int argc,
    char ** argv)
{
    bool error_seen, index_keys, all_keys, block_info, csv_header, counter_info,
        running, no_csv, summary_only;
    int error_counter;
    char ** cursor;

    running=true;
    error_seen=false;

    block_info=false;
    counter_info=false;
    index_keys=false;
    csv_header=false;
    all_keys=false;
    no_csv=false;
    summary_only=false;

    error_counter=0;


    for (cursor=argv+1; NULL!=*cursor && running; ++cursor)
    {
        // option flag?
        if ('-'==**cursor)
        {
            char flag;

            flag=*((*cursor)+1);
            switch(flag)
            {
                case 'b':  block_info=true; break;
                case 'c':  counter_info=true; break;
                case 'h':  csv_header=true; break;
                case 'i':  index_keys=true; break;
                case 'k':  all_keys=true; break;
                case 'n':  no_csv=true; break;
                case 's':  summary_only=true; break;
                default:
                    fprintf(stderr, " option \'%c\' is not valid\n", flag);
                    command_help();
                    running=false;
                    error_counter=1;
                    error_seen=true;
                    break;
            }   // switch
        }   // if

        // sst file
        else
        {
            leveldb::Options options;
            leveldb::DoubleCache double_cache(options);
            leveldb::ReadOptions read_options;
            std::string table_name, dbname, path_temp;
            leveldb::Env * env;
            leveldb::FileMetaData meta;
            leveldb::TableCache * table_cache;
            env=leveldb::Env::Default();

            const int search_level = -2;
            const bool is_overlapped = search_level < 3; // temporary: see TableCache::Evict()

            // make copy since basename() and dirname() may modify
            path_temp=*cursor;
            dbname=dirname((char *)path_temp.c_str());
            dbname=MakeTieredDbname(dbname, options);
            path_temp=*cursor;
            table_name=basename((char *)path_temp.c_str());
            meta.number=strtol(table_name.c_str(), NULL, 10);

            options.filter_policy=leveldb::NewBloomFilterPolicy(10);
            table_cache=new leveldb::TableCache(dbname, &options, double_cache.GetFileCache(), double_cache);
            table_name = leveldb::TableFileName(options, meta.number, search_level);

            // open table, step 1 get file size
            leveldb::Status status = env->GetFileSize(table_name, &meta.file_size);
            if (!status.ok())
            {
                fprintf(stderr, "%s: GetFileSize failed (%s)\n", table_name.c_str(),status.ToString().c_str());
                error_seen=true;
                error_counter=10;
            }   // if

            //open table, step 2 find table (cache or open)
            if (status.ok())
            {
                leveldb::Cache::Handle * fhandle;

                fhandle=NULL;

                status=table_cache->TEST_FindTable(meta.number, meta.file_size, search_level, &fhandle);

                // count keys and size keys/filter
                if (status.ok())
                {
                    leveldb::Table* table;
                    leveldb::Iterator *it, *it2;
                    int count, count2, total, block_count;
                    size_t tot_size, smallest_block, tot_compress, tot_uncompress;
                    bool first;
                    leveldb::Status status;
                    leveldb::RandomAccessFile * file;

                    total=0;
                    count=0;
                    count2=0;
                    tot_size=0;

                    table = reinterpret_cast<leveldb::TableAndFile*>(table_cache->TEST_GetInternalCache()->Value(fhandle))->table;
                    file = reinterpret_cast<leveldb::TableAndFile*>(table_cache->TEST_GetInternalCache()->Value(fhandle))->file;
                    it = table->TEST_GetIndexBlock()->NewIterator(options.comparator);


                    // walk keys in index block
                    if (index_keys)
                    {
                        for (it->SeekToFirst(), count=0; it->Valid(); it->Next())
                        {
                            ++count;
                            if (it->status().ok())
                            {
                                leveldb::ParsedInternalKey parsed;
                                leveldb::Slice key = it->key();
                                leveldb::Slice value = it->value();

                                ParseInternalKey(key, &parsed);
                                printf("key %zd, value %zd: %s\n", key.size(), value.size(), parsed.DebugStringHex().c_str());
                            }   // if
                            else
                            {
                                fprintf(stderr, "%s: index iterator failed (%s)\n", table_name.c_str(),it->status().ToString().c_str());
                            }   // else
                        }   // for
                    }   // if

                    // Walk all blocks (but nothing within block)
                    smallest_block=0;
                    first=true;
                    block_count=0;
                    tot_compress=0;
                    tot_uncompress=0;

                    for (it->SeekToFirst(), count=0; it->Valid() && !summary_only; it->Next())
                    {
                        leveldb::BlockContents contents;
                        leveldb::BlockHandle bhandle;
                        leveldb::Slice slice;

                        ++block_count;
                        slice=it->value();
                        bhandle.DecodeFrom(&slice);

                        if (block_info)
                        {
                            printf("block %d, offset %" PRIu64 ", size %" PRIu64 ", next %" PRIu64 "\n",
                                   block_count, bhandle.offset(), bhandle.size(), bhandle.offset()+bhandle.size());
                        }   // if

                        tot_compress+=bhandle.size();
                        status=leveldb::ReadBlock(file, read_options, bhandle, &contents);
                        if (status.ok())
                        {
                            if (first)
                            {
                                first=false;
                                smallest_block=contents.data.size();
                            }   // if
                            else if (contents.data.size()<smallest_block)
                            {
                                smallest_block=contents.data.size();
                            }   // else if
                            tot_uncompress+=contents.data.size();

                            if (contents.heap_allocated)
                            {
                                delete [] contents.data.data();
                            }   // if
                        }   // if
                        else
                        {
                            fprintf(stderr, "ReadBlock failed on block %d\n", block_count);
                        }   // else
                    }   // for

                    // Walk all keys in each block.
                    for (it->SeekToFirst(), count=0; it->Valid() && !summary_only; it->Next())
                    {
                        ++count;
                        it2=leveldb::Table::TEST_BlockReader(table, read_options, it->value());
                        for (it2->SeekToFirst(), count2=0; it2->Valid(); it2->Next())
                        {
                            ++count2;
                            ++total;
                            if (it2->status().ok())
                            {
                                tot_size+=it2->value().size();

                                if (all_keys)
                                {
                                    leveldb::ParsedInternalKey parsed;
                                    leveldb::Slice key = it2->key();

                                    ParseInternalKey(key, &parsed);
                                    printf("%s block_key %s\n", parsed.DebugStringHex().c_str(), table_name.c_str());
                                }   // if
                            }   // if
                            else
                            {
                                fprintf(stderr, "%s: value iterator failed, location [%d, %d] (%s)\n",
                                       table_name.c_str(),count, count2,it2->status().ToString().c_str());
                            }   // else
                        }   // for

                        delete it2;
                    }   // for

                    delete it;

                    if (!no_csv)
                    {
                        if (csv_header)
                        {
                            csv_header=false;
                            printf("Table File, File size, Index size, Index key count, ");
                            printf("total key count, total value size, average value size, smallest block, ratio*100, ");
                            printf("table object size, filter size");

                            if (counter_info)
                            {
                                unsigned loop;
                                leveldb::SstCounters counters;

                                counters=table->GetSstCounters();

                                for (loop=0; loop<counters.Size(); ++loop)
                                    printf(", Counter %u", loop);
                            }   // if

                            printf("\n");
                        }   // if

                        printf("%s, %" PRIu64 ", %zd, %d,",
                               table_name.c_str(), meta.file_size, table->TEST_GetIndexBlock()->size(), count);

                        printf(" %d, %zd, %zd, %zd, %zd,",
                               total, tot_size, (0!=total) ? tot_size/total : 0, smallest_block,
                               (0!=tot_compress) ? (tot_uncompress*100)/tot_compress: 0);

                        printf(" %zd, %zd",
                               table->TEST_TableObjectSize(), table->TEST_FilterDataSize());

                        if (counter_info || summary_only)
                        {
                            unsigned loop;
                            leveldb::SstCounters counters;

                            counters=table->GetSstCounters();

                            for (loop=0; loop<counters.Size(); ++loop)
                                printf(", %" PRIu64 "", counters.Value(loop));
                        }   // if

                        printf("\n");
                    }   // if

                    // cleanup
                    table_cache->Evict(meta.number, is_overlapped);
                }   // if
                else
                {
                    fprintf(stderr, "%s: FindTable failed (%s)\n", table_name.c_str(),status.ToString().c_str());
                    error_seen=true;
                    error_counter=1;
                }   // else
            }   // if

            // cleanup
            delete table_cache;
            delete options.filter_policy;

        }   // else
    }   // for

    if (1==argc)
        command_help();

    return( error_seen && 0!=error_counter ? 1 : 0 );

}   // main


void
command_help()
{
    fprintf(stderr, "sst_scan [option | file]*\n");
    fprintf(stderr, "  options\n");
    fprintf(stderr, "      -b  print details about block\n");
    fprintf(stderr, "      -c  print sst counters\n");
    fprintf(stderr, "      -h  print csv formatted header line (once)\n");
    fprintf(stderr, "      -i  print index keys\n");
    fprintf(stderr, "      -k  print all keys\n");
    fprintf(stderr, "      -n  NO csv data (or header)\n");
}   // command_help

namespace leveldb {


}  // namespace leveldb

