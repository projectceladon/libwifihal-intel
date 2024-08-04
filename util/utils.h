/*
 * Copyright (C) 2015 Intel Deutschland GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdlib.h>
#include <string.h>
#include <hardware_legacy/wifi_hal.h>
#include "list.h"

#ifndef BIT
#define BIT(_x) (1 << (_x))
#endif

#define ETH_ALEN	6

#ifndef MAC2STR
#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"
#endif

#ifndef offsetof
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif

#ifdef ANDROID
#include <cutils/properties.h>
#else
#define PROPERTY_VALUE_MAX 92
static inline int property_get(const char *key, char *value, const char *default_value)
{
	int len;
	if (!default_value)
		return 0;

	len = strlen(default_value);
	memcpy(value, default_value, len + 1);
	return len;
}
#endif

#define MUTEX_LOCK(_mutex) ({							\
	int _ret = pthread_mutex_lock(_mutex);					\
	if (_ret)								\
		hal_printf(MSG_ERROR, "could not lock mutex to perform %s,	\
					error number %d", __func__, _ret);	\
	(_ret);									\
})

#define MUTEX_UNLOCK(_mutex) ({						\
	int _ret = pthread_mutex_unlock(_mutex);				\
	if (_ret)								\
		hal_printf(MSG_ERROR, "could not unlock mutex in %s,		\
					error number %d", __func__, _ret);	\
	(_ret);									\
})

#define IN_RANGE(var, min, max) ((var) <= (max) && (var) >= (min))

static inline void *zalloc(size_t size)
{
	void *ptr = malloc(size);
	if (ptr)
		memset(ptr, 0, size);
	return ptr;
}
#endif /* __UTILS_H__ */
