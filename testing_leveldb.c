#include "osd_leveldb.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include "log.h"
void leveldb_range_print(leveldb_range_t * r) {
    if (!r->head && !r->tail) {
       printf("empty range\n");
    }
    printf("Dumping range %p head: %p tail %p \n", r, r->head, r->tail);
    leveldb_rangeelem_t * curr;
    for (curr = r->head; curr != NULL; curr = curr->next) {
        if (curr->next != NULL) {
            assert(curr->next->prev == curr);
            assert(curr->next->left > curr->right);
        } else {
            assert(r->tail == curr);
        }
        if (curr->prev != NULL) {
            assert(curr->prev->next == curr);
        } else {
            assert(r->head == curr);
        }
        printf("  %p: [%lld %lld] left:%lld\n", curr, curr->left, curr->right, curr->buffer_left);
    }
}
void test_fd();
void test_ranges();
void test_state();
int main(int argc, char ** argv) {
    apr_initialize();
    set_log_level(20);
    test_fd();
    test_ranges();
    test_state();
}
void test_fd() {
    leveldb_fs_t * db = leveldb_fs_open("testing_leveldb_scratchdb");
    size_t buf_size = 1024 * 1024;
    void * buf1 = malloc(buf_size);
    void * buf2 = malloc(buf_size);
    void * buf3 = malloc(buf_size);
    void * buf4 = malloc(buf_size);
    memset(buf1, 1, buf_size);
    memset(buf2, 2, buf_size);
    memset(buf3, 3, buf_size);
    memset(buf4, 4, buf_size);
    leveldb_state_t * state = leveldb_state_create(db, 2);
    leveldb_fd_t * fd = leveldb_fd_create(db, state);
    leveldb_fd_write(fd, 0 * buf_size, buf_size, buf1);
    leveldb_fd_write(fd, 1 * buf_size, buf_size, buf2);
    leveldb_fd_write(fd, 2 * buf_size, buf_size, buf3);
    leveldb_fd_write(fd, 3 * buf_size, buf_size, buf4);
    char outbuf[10];
    assert(leveldb_fd_read(fd, 0, 1, &outbuf) == 1);
    assert(outbuf[0] == 1);
    assert(leveldb_fd_read(fd, 10, 1, &outbuf) == 1);    
    assert(outbuf[0] == 1);
    assert(leveldb_fd_read(fd, buf_size + 1, 1, &outbuf) == 1);    
    assert(outbuf[0] == 2);
    size_t len = leveldb_fd_read(fd, buf_size - 1, 2, &outbuf);
    assert(len == 2);    
    assert(outbuf[0] == 1);
    assert(outbuf[1] == 2);
    len = leveldb_fd_read(fd, buf_size - 1, 10, &outbuf);
    leveldb_fd_write(fd, 0 , buf_size, buf1);
    leveldb_fd_write(fd, 1 * buf_size / 2, buf_size, buf2);
    leveldb_fd_write(fd, 2 * buf_size / 2, buf_size, buf3);
    leveldb_fd_write(fd, 3 * buf_size / 2, buf_size, buf4);
    len = leveldb_fd_read(fd, buf_size - 1, 2, &outbuf);
    assert(len == 2);    
    assert(outbuf[0] == 2);
    assert(outbuf[1] == 3);
    leveldb_fd_write(fd, 3 * buf_size / 2, buf_size, buf4);
    leveldb_fd_write(fd, 2 * buf_size / 2, buf_size, buf3);
    leveldb_fd_write(fd, 1 * buf_size / 2, buf_size, buf2);
    leveldb_fd_write(fd, 0 , buf_size, buf1);
    len = leveldb_fd_read(fd, buf_size - 1, 2, &outbuf);
    assert(len == 2);    
    assert(outbuf[0] == 1);
    assert(outbuf[1] == 2);


    leveldb_fd_destroy(fd);
    leveldb_state_destroy(state);
    leveldb_fs_close(db);
}
void test_state() {
    leveldb_fs_t * db = leveldb_fs_open("testing_leveldb_scratchdb");
    assert(db);
    leveldb_state_t * state = leveldb_state_create(db, 1);
    assert(state);
    // shouldn't exist
    assert(!leveldb_state_read(state, 1000, 42)->head);
    leveldb_command_t * cmd1 = leveldb_command_create();
    assert(cmd1);
    char * buf;
    size_t len;
    buf = leveldb_state_command_to_string(cmd1, &len);
    assert(buf);
    assert(len);
    cmd1->off = 1;
    cmd1->len = 2;
    cmd1->command = 3;
    buf = leveldb_state_command_to_string(cmd1, &len);
    assert(buf);
    assert(len);
    leveldb_command_t * cmd2 = leveldb_state_string_to_command(buf, len);
    assert(cmd2 && (cmd2->off == 1) && (cmd2->len == 2) && (cmd2->command == 3));
    leveldb_command_destroy(cmd2);
    char * buffer_test = "Testing a buffer key";
    size_t buffer_len = strlen(buffer_test);
    cmd1->buffer_key = strdup(buffer_test);
    cmd1->buffer_key_len = buffer_len;
    buf = leveldb_state_command_to_string(cmd1, &len);
    cmd2 = leveldb_state_string_to_command(buf, len);
    assert((cmd2->buffer_key_len == buffer_len) &&
                (strncmp(buffer_test, cmd2->buffer_key, buffer_len) == 0));
    leveldb_command_destroy(cmd2);
    assert( !leveldb_state_write(state, 0, 10, 0, buffer_test, buffer_len));
    leveldb_range_t * range = leveldb_state_read(state, 4, 2);
    assert(range && (strncmp(range->head->buffer_key, buffer_test, buffer_len) == 0));
    leveldb_range_destroy(range);

    // put an overwrite into the log
    char * buffer_test2 = "This buffer is in the middle";
    size_t buffer_len2 = strlen(buffer_test2);
    assert( !leveldb_state_write(state, 2, 6, 0, buffer_test2, buffer_len2));
    leveldb_range_print(state->range);
    range = leveldb_state_read(state, 0, 5);
    assert(range && (strncmp(range->head->buffer_key, buffer_test, buffer_len) == 0));
    assert(range && (strncmp(range->tail->buffer_key, buffer_test2, buffer_len2) == 0));
    leveldb_range_destroy(range);
    leveldb_state_destroy(state);

    // reload the log from the DB and make sure we get the same thing
    state = leveldb_state_create(db, 1);
    assert(!leveldb_state_replay(state));
    leveldb_range_print(state->range);
    range = leveldb_state_read(state, 0, 5);
    assert(range && (strncmp(range->head->buffer_key, buffer_test, buffer_len) == 0));
    assert(range && (strncmp(range->tail->buffer_key, buffer_test2, buffer_len2) == 0));
    leveldb_range_destroy(range);
    range = leveldb_state_read(state, 5, 4);
    assert(range && (strncmp(range->head->buffer_key, buffer_test2, buffer_len2) == 0));
    assert(range && (strncmp(range->tail->buffer_key, buffer_test, buffer_len) == 0));

    leveldb_fs_close(db);
}

void test_ranges() {
    leveldb_range_t * r = leveldb_range_create();
    assert(r);
    assert(leveldb_position_search(r, 5) == NULL);
    printf("range 1 - insert\n");
    leveldb_rangeelem_t * range1 = leveldb_range_insert(r,2, 8, 0, "range1", 6);
    leveldb_range_print(r);
    assert(range1);
    assert(r->head == range1);
    assert(r->tail == range1);
    assert(leveldb_position_search(r, 1) == NULL);
    assert(leveldb_position_search(r, 2) == range1);
    assert(leveldb_position_search(r, 3) == range1);
    assert(leveldb_position_search(r, 8) == range1);
    assert(leveldb_position_search(r, 9) == NULL);

    // test wedging to the left
    printf("range 2 - insert left\n");
    leveldb_rangeelem_t * range2 = leveldb_range_insert(r,1, 3, 0, "range2", 6);
    leveldb_range_print(r);
    assert(range2);
    assert(r->head == range2);
    assert(r->tail == range1);
    assert(leveldb_position_search(r, 0) == NULL);
    assert(leveldb_position_search(r, 1) == range2);
    assert(leveldb_position_search(r, 3) == range2);
    assert(leveldb_position_search(r, 4) == range1);
    assert(range1->buffer_left == 2);

    // test wedging to the right
    printf("range 3 - insert right\n");
    leveldb_rangeelem_t * range3 = leveldb_range_insert(r,7, 9, 0, "range3", 6);
    leveldb_range_print(r);
    assert(range3);
    assert(r->head == range2);
    assert(r->tail == range3);
    assert(leveldb_position_search(r, 0) == NULL);
    assert(leveldb_position_search(r, 6) == range1);
    assert(leveldb_position_search(r, 7) == range3);
    assert(leveldb_position_search(r, 9) == range3);
    assert(leveldb_position_search(r, 10) == NULL);

    // test overlapping everythign
    printf("range 4 - overlap\n");
    leveldb_rangeelem_t * range4 = leveldb_range_insert(r,0, 9, 0, "range4", 6);
    leveldb_range_print(r);
    assert(range4);
    assert(r->head == range4);
    assert(r->tail == range4);
    assert(leveldb_position_search(r, 0) == range4);
    assert(leveldb_position_search(r, 3) == range4);
    assert(leveldb_position_search(r, 5) == range4);
    assert(leveldb_position_search(r, 7) == range4);
    assert(leveldb_position_search(r, 10) == NULL);

    // test middle element
    printf("range 5 - insert to middle\n");
    leveldb_rangeelem_t * range5 = leveldb_range_insert(r,1, 3, 0, "range5", 6);
    leveldb_range_print(r);
    assert(range5);
    assert(r->head == range4);
    assert(leveldb_position_search(r, 0) == range4);
    assert(leveldb_position_search(r, 1) == range5);
    assert(leveldb_position_search(r, 3) == range5);
    assert(leveldb_position_search(r, 4) != range4);
    printf("range 6 - loop left to right\n");
    int i;
    for (i = 0; i < 10; i += 2) {
        leveldb_rangeelem_t * range6 = leveldb_range_insert(r,i, i, 0, "range6", 6);
        leveldb_range_print(r);
        assert(leveldb_position_search(r, i) == range6);
        assert(range6);
    }
    leveldb_range_print(r);

    //blow everything away
    printf("range 7 - blow it away\n");
    leveldb_rangeelem_t * range7 = leveldb_range_insert(r,0, 10, 0, "range7", 6);
    leveldb_range_print(r);
    assert(leveldb_position_search(r, 10) == range7);

    //blow everything away
    printf("range 8 - blow it away v2\n");
    leveldb_rangeelem_t * range8 = leveldb_range_insert(r,0, 10, 0, "range8", 6);
    leveldb_range_print(r);
    assert(leveldb_position_search(r, 10) == range8);
    assert(leveldb_position_search(r, 0) == range8);

    //blow everything away
    printf("range 9 - blow it away v2\n");
    leveldb_rangeelem_t * range9 = leveldb_range_insert(r,0, 11, 0, "range8", 6);
    leveldb_range_print(r);
    assert(leveldb_position_search(r, 11) == range9);
    assert(leveldb_position_search(r, 0) == range9);


}
