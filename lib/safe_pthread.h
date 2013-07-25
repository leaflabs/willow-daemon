/* Copyright (c) 2013 LeafLabs, LLC.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file lib/safe_pthread.h
 *
 * Pthread wrapper routines which make errors fatal. This lets you
 * call them and not check the result.
 *
 * They also provide some other conveniences over the standard pthread API.
 */

#ifndef _LIB_SAFE_PTHREAD_H_
#define _LIB_SAFE_PTHREAD_H_

#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#ifdef SAFE_PTHREAD_DEBUG_LOG
#include "logging.h"
#define SAFE_PTHREAD_LOG log_DEBUG
#else
#define SAFE_PTHREAD_LOG(...) ((void)0)
#endif

#define safe_p_cond_wait(cv, mtx)                                        \
    do { SAFE_PTHREAD_LOG("%s: cond_wait(%s, %s)", __func__, #cv, #mtx); \
         __safe_p_cond_wait(cv, mtx); } while (0)
#define safe_p_mutex_lock(mtx)                                  \
    do { SAFE_PTHREAD_LOG("%s: lock(%s)", __func__, #mtx);      \
        __safe_p_mutex_lock(mtx); } while (0)
#define safe_p_mutex_trylock(mtx)                               \
    ({ SAFE_PTHREAD_LOG("%s: trylock(%s)", __func__, #mtx);     \
       __safe_p_mutex_trylock(mtx); })
#define safe_p_mutex_unlock(mtx)                                \
    do { SAFE_PTHREAD_LOG("%s: unlock(%s)", __func__, #mtx);    \
        __safe_p_mutex_unlock(mtx); } while (0)
#define safe_p_cond_signal(cv)                                  \
    do { SAFE_PTHREAD_LOG("%s: signal(%s)", __func__, #cv);     \
        __safe_p_cond_signal(cv); } while (0)
#define safe_p_join(t, rv)                                      \
    do { SAFE_PTHREAD_LOG("%s: join(%s)", __func__, #t);        \
         __safe_p_join(t, rv); } while (0)
#define safe_p_rwlock_rdlock(mtx)                                       \
    do { SAFE_PTHREAD_LOG("%s: rwlock_rdlock(%s)", __func__, #mtx);     \
        __safe_p_rwlock_rdlock(mtx); } while (0)
#define safe_p_rwlock_wrlock(mtx)                                       \
    do { SAFE_PTHREAD_LOG("%s: rwlock_wrlock(%s)", __func__, #mtx);     \
        __safe_p_rwlock_wrlock(mtx); } while (0)
#define safe_p_rwlock_trywrlock(mtx)                                    \
    ({ SAFE_PTHREAD_LOG("%s: rwlock_trywrlock(%s)", __func__, #mtx);    \
        __safe_p_rwlock_trywrlock(mtx); })
#define safe_p_rwlock_unlock(mtx)                                       \
    do { SAFE_PTHREAD_LOG("%s: rwlock_unlock(%s)", __func__, #mtx);     \
        __safe_p_rwlock_unlock(mtx); } while (0)
#define safe_p_cancel(t)                                        \
    do { SAFE_PTHREAD_LOG("%s: cancel(%s)", __func__, #t);      \
        __safe_p_cancel(t); } while (0)

static inline void __safe_p_cond_wait(pthread_cond_t *cv,
                                      pthread_mutex_t *mtx)
{
    int en = pthread_cond_wait(cv, mtx);
    if (en) {
        abort();
    }
}

static inline void __safe_p_mutex_lock(pthread_mutex_t *mtx)
{
    int en = pthread_mutex_lock(mtx);
    if (en) {
        abort();
    }
}

static inline int __safe_p_mutex_trylock(pthread_mutex_t *mtx)
{
    int en = pthread_mutex_trylock(mtx);
    if (en != 0 && en != EBUSY) {
        abort();
    }
    return en;
}

static inline void __safe_p_mutex_unlock(pthread_mutex_t *mtx)
{
    int en = pthread_mutex_unlock(mtx);
    if (en) {
        abort();
    }
}

static inline void __safe_p_cond_signal(pthread_cond_t *cv)
{
    int en = pthread_cond_signal(cv);
    if (en) {
        abort();
    }
}

static inline void __safe_p_join(pthread_t t, void **retval)
{
    void *rv;
    if (!retval) {
        retval = &rv;
    }
    int en = pthread_join(t, retval);
    if (en) {
        abort();
    }
}

static inline void __safe_p_rwlock_rdlock(pthread_rwlock_t *rw)
{
    int en = pthread_rwlock_rdlock(rw);
    if (en) {
        abort();
    }
}

static inline void __safe_p_rwlock_wrlock(pthread_rwlock_t *rw)
{
    int en = pthread_rwlock_wrlock(rw);
    if (en) {
        abort();
    }
}

static inline int __safe_p_rwlock_trywrlock(pthread_rwlock_t *rw)
{
    int en = pthread_rwlock_trywrlock(rw);
    if (en != 0 && en != EBUSY) {
        abort();
    }
    return en;
}

static inline void __safe_p_rwlock_unlock(pthread_rwlock_t *rw)
{
    int en = pthread_rwlock_unlock(rw);
    if (en) {
        abort();
    }
}

static inline void __safe_p_cancel(pthread_t t)
{
    int en = pthread_cancel(t);
    if (en) {
        abort();
    }
}

#endif
