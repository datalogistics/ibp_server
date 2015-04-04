//
// leveldb_range_* - implementation of range datastructure mapping allocation
//                   byte ranges to payload IDs. Thread unsafe.
//
#include <assert.h>
#include "log.h"
#include "osd_leveldb.h"
#include <stdlib.h>

#define LEVELDB_RANGE_PARANOID 0
#if LEVELDB_RANGE_PARANOID
int leveldb_range_validate(leveldb_range_t * r) {
    assert((r->head == NULL) == (r->tail == NULL));
    assert((r->initialized == 0) || (r->initialized == 1));
    leveldb_rangeelem_t * iter;
    for (iter = r->head; iter != NULL; iter = iter->next) {
        if (iter->prev) {
            assert(iter->prev->next == iter);
        }
        if (iter->next) {
            assert(iter->next->prev == iter);
        } else {
            assert(iter == r->tail);
        }
    }
    for (iter = r->tail; iter != NULL; iter = iter->prev) {
        if (iter->next) {
            assert(iter->next->prev == iter);
        }
        if (iter->prev) {
            assert(iter->prev->next == iter);
        } else {
            assert(iter == r->head);
        }
    }
    return 1;
}
#else
int leveldb_range_validate(leveldb_range_t * r) {
    return 1;
}
#endif
void leveldb_range_truncate(leveldb_range_t *r, osd_off_t len) {
    if (r->head == NULL && r->tail == NULL) {
        return;
    }
    leveldb_rangeelem_t * curr;
    for (curr = r->tail; curr != NULL; curr = curr->prev) {
        if (curr->left > len) {
            r->tail = curr;
            leveldb_rangeelem_destroy(curr);
        } else if ((curr->left < len) && (curr->right >= len)) {
            curr->right = len;
            break;
        }
    }
}
leveldb_rangeelem_t * leveldb_range_insert(leveldb_range_t * r, osd_off_t left,
                                           osd_off_t right, osd_off_t buffer_left,
                                           char * buffer_key, size_t buffer_key_len) {
    leveldb_range_validate(r);
    leveldb_rangeelem_t * elem = leveldb_rangeelem_create(left, right, buffer_left, buffer_key, buffer_key_len);
   //printf("Inserting %p [%lld %lld]\n", elem, left, right);
    if (!elem) { return NULL; };
    // special case
    if (r->head == NULL && r->tail == NULL) {
        r->head=elem;
        r->tail=elem;
        elem->next = NULL;
        elem->prev = NULL;
        leveldb_range_validate(r);
        return elem;
    }
    if ( (r->head == NULL) != (r->tail == NULL) ) {
        // Something bad's happened
        return NULL;
    }
    
    leveldb_rangeelem_t * i;
    leveldb_rangeelem_t * split_curr;
    leveldb_rangeelem_t * left_anchor = NULL;
    leveldb_rangeelem_t * right_anchor = NULL;
    for (i = r->tail; (i != NULL); i = i->prev) {
        assert(i != i->prev);
        assert(i != i->next);
       //printf(" examining [%lld %lld] against [%lld %lld]h: %p t: %p c: %p\n", i->left, i->right, left, right, r->head, r->tail, i);
        // left and right anchor cuddle around elem, on top if necessary
        if (i->right > right) {
            right_anchor = i;
        }
        if (i->left < left) {
            left_anchor = i;
           //printf(" examining wrapped at [%lld %lld]: %p\n", i->left, i->right, i);
            break;
        }
    }
   //printf("Got left_anchor: %p right_anchor: %p\n", left_anchor, right_anchor);
    if ((left_anchor != NULL) && (left_anchor == right_anchor)) {
        // Handle the case there elem fits inside of curr
        // |       left_anchor             |
        //             | elem |
        // |left_anchor| elem | split_curr |
        split_curr = leveldb_rangeelem_create(right + 1,
                                                right_anchor->right, 
                                                right_anchor->buffer_left + right - right_anchor->left + 1, 
                                                right_anchor->buffer_key, 
                                                right_anchor->buffer_key_len);
        if (!split_curr) { return NULL; }
       //printf("Made a new split range: %p [%lld %lld]\n", split_curr, split_curr->left, split_curr->right);
        left_anchor->right = left - 1;
        // fix forward links
        leveldb_rangeelem_t * right_side = right_anchor->next;
        left_anchor->next = elem;
        elem->next = split_curr;
        if (right_side) {
            split_curr->next = right_side;
            right_side->prev = split_curr;
        } else {
            r->tail = split_curr;
        }
        // go backwards
        split_curr->prev = elem;
        elem->prev = left_anchor;
        
        leveldb_range_validate(r);
        return elem;
    }

    // Phase 1 - insert elem into the right part of the list
    leveldb_rangeelem_t * delete_start = NULL;
    if (!left_anchor) {
       //printf("Resetting head\n");
        delete_start = r->head;
        r->head = elem;
    } else {
        delete_start = left_anchor;
        left_anchor->next = elem;
    }
    elem->prev = left_anchor;

    if (!right_anchor) {
       //printf("Resetting tail\n");
        r->tail = elem;
    } else {
        right_anchor->prev = elem;
    }
    elem->next = right_anchor;
    
    // delete everything fully overlapped
    for (i = delete_start; i != NULL; i = i->next) {
        if ((i != elem) && (i->left >= elem->left) && (i->right <= elem->right)) {
            // remove this element
            leveldb_rangeelem_destroy(i);
        }
    }
    // Phase 2 - trim the left and right anchors
    if (left_anchor) {
        left_anchor->right = left - 1;
    }
    if (right_anchor) {
        right_anchor->buffer_left += right - right_anchor->left + 1;
        right_anchor->left = right + 1;
    }
    leveldb_range_validate(r);
    return elem;
}

leveldb_rangeelem_t * leveldb_position_search(leveldb_range_t * r, osd_off_t pos) {
    leveldb_range_validate(r);
    leveldb_rangeelem_t * curr;
    for (curr = r->head; curr != NULL; curr = curr->next) {
        if ((pos >= curr->left) && (pos <= curr->right)) {
            return curr;
        }
    }
    return NULL;
}

// returns NULL on an error
leveldb_range_t * leveldb_range_search(leveldb_range_t * r, osd_off_t pos, osd_off_t len) {
    leveldb_range_validate(r);
    leveldb_range_t * ret = leveldb_range_create();
    if (!ret) { return ret; };
    leveldb_rangeelem_t * left_pos = leveldb_position_search(r, pos);
    if (!left_pos) { return ret; }
    ret->head = leveldb_rangeelem_copy(left_pos);
    if (!ret->head) { goto failure; }
    ret->tail = ret->head;
    ret->head->next = NULL;
    ret->head->prev = NULL;
    leveldb_rangeelem_t * curr;
    leveldb_rangeelem_t * ret_curr;
    ret_curr = left_pos;
    for (curr = left_pos->next; curr != NULL; curr = curr->next) {
        if (curr->left >= (pos + len)) {
            break;
        }
        leveldb_rangeelem_t * new_elem = leveldb_rangeelem_copy(curr);
        if (new_elem == NULL) {
            goto failure;
        }
        new_elem->prev = ret->tail;
        new_elem->next = NULL;
        ret->tail->next = new_elem;
        ret->tail = new_elem;
    }
    assert(ret->head->left <= pos);
    assert(ret->tail->right >= pos + len - 1);
    leveldb_range_validate(ret);
    return ret;

failure:
    log_printf(0, "Range search failed\n");
    leveldb_range_destroy(ret);
    return NULL;
}

leveldb_rangeelem_t * leveldb_rangeelem_copy(leveldb_rangeelem_t * other) {
    leveldb_rangeelem_t * ret = leveldb_rangeelem_create(other->left,
                                                        other->right,
                                                        other->buffer_left,
                                                        other->buffer_key,
                                                        other->buffer_key_len);

   //printf("Copying elem %p into %p\n", other, ret);
    return ret;
}

leveldb_rangeelem_t * leveldb_rangeelem_create(osd_off_t left, osd_off_t right,
                                              osd_off_t buffer_left,
                                              char * buffer_key, size_t buffer_key_len) {
    leveldb_rangeelem_t * elem = malloc(sizeof(leveldb_rangeelem_t));
    if (!elem) {
        return NULL;
    }
    memset(elem, 0, sizeof(leveldb_rangeelem_t));
    if (buffer_key_len) {
        elem->buffer_key = malloc(buffer_key_len);
        if (!elem->buffer_key) {
            free(elem);
            return NULL;
        }
        memcpy(elem->buffer_key, buffer_key, buffer_key_len);
    }
    elem->left = left;
    elem->right = right;
    elem->buffer_left = buffer_left;
    elem->buffer_key_len = buffer_key_len;
    elem->prev = NULL;
    elem->next = NULL;
    return elem;
}

void leveldb_rangeelem_destroy(leveldb_rangeelem_t * elem) {
   //printf("Destroying rangelem %p\n", elem);
    if (elem) {
        if (elem->buffer_key) {
            free(elem->buffer_key);
        }
        free(elem);
    }
}

leveldb_range_t * leveldb_range_create() {
    leveldb_range_t * ret = malloc(sizeof(leveldb_range_t));
    if (ret) {
        memset(ret, 0, sizeof(leveldb_range_t));
    }
    leveldb_range_validate(ret);
    return ret;
}

void leveldb_range_destroy(leveldb_range_t * r) {
    leveldb_rangeelem_t * curr;
    for (curr = r->head; curr != NULL; ) {
            leveldb_rangeelem_t * next = curr->next;
            leveldb_rangeelem_destroy(curr);
            curr = next;
    }
    free(r);
}
