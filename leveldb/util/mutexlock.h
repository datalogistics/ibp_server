// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#ifndef STORAGE_LEVELDB_UTIL_MUTEXLOCK_H_
#define STORAGE_LEVELDB_UTIL_MUTEXLOCK_H_

#include "port/port.h"

namespace leveldb {

// Helper class that locks a mutex on construction and unlocks the mutex when
// the destructor of the MutexLock object is invoked.
//
// Typical usage:
//
//   void MyClass::MyMethod() {
//     MutexLock l(&mu_);       // mu_ is an instance variable
//     ... some complex code, possibly with multiple return paths ...
//   }

class MutexLock {
 public:
  explicit MutexLock(port::Mutex *mu) : mu_(mu) {
    this->mu_->Lock();
  }
  ~MutexLock() { this->mu_->Unlock(); }

 private:
  port::Mutex *const mu_;
  // No copying allowed
  MutexLock(const MutexLock&);
  void operator=(const MutexLock&);
};


class SpinLock {
 public:
  explicit SpinLock(port::Spin *sp) : sp_(sp) {
    this->sp_->Lock();
  }
  ~SpinLock() { this->sp_->Unlock(); }

 private:
  port::Spin *const sp_;
  // No copying allowed
  SpinLock(const SpinLock&);
  void operator=(const SpinLock&);
};


class ReadLock {
 public:
  explicit ReadLock(port::RWMutex *mu) : mu_(mu) {
    this->mu_->ReadLock();
  }
  ~ReadLock() { this->mu_->Unlock(); }

 private:
  port::RWMutex *const mu_;
  // No copying allowed
  ReadLock(const ReadLock&);
  void operator=(const ReadLock&);
};


class WriteLock {
 public:
  explicit WriteLock(port::RWMutex *mu) : mu_(mu) {
    this->mu_->WriteLock();
  }
  ~WriteLock() { this->mu_->Unlock(); }

 private:
  port::RWMutex *const mu_;
  // No copying allowed
  WriteLock(const WriteLock&);
  void operator=(const WriteLock&);
};

}  // namespace leveldb


#endif  // STORAGE_LEVELDB_UTIL_MUTEXLOCK_H_
