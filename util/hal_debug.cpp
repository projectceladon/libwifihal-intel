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

#include "hal_debug.h"
#include <stdarg.h>
#include <stdio.h>

#ifdef CONFIG_DEBUG_SYSLOG
#include <syslog.h>
static int hal_debug_syslog = 0;

#endif /* CONFIG_DEBUG_SYSLOG */

#ifdef CONFIG_ANDROID_LOG
#include <android/log.h>

static int hal_to_android_level(int level)
{
	switch (level) {
	case MSG_ERROR:
		return ANDROID_LOG_ERROR;
	case MSG_WARNING:
		return ANDROID_LOG_WARN;
	}
	return ANDROID_LOG_DEBUG;
}

#endif /* CONFIG_ANDROID_LOG */

#ifndef LOG_NAME
#define LOG_NAME "wifi hal"

#endif /* LOG_NAME */

#ifdef CONFIG_DEBUG
static int hal_debug_level = CONFIG_DEBUG;
#else
static int hal_debug_level = MSG_ERROR;
#endif

#ifdef CONFIG_DEBUG_SYSLOG

void hal_debug_open_syslog(void)
{
	openlog(LOG_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
	hal_debug_syslog++;
}


void hal_debug_close_syslog(void)
{
	closelog();
	hal_debug_syslog = 0;
}


static int syslog_priority(int level)
{
	switch (level) {
	case MSG_WARNING:
		return LOG_WARNING;
	case MSG_ERROR:
		return LOG_ERR;
	}
	return LOG_DEBUG;
}
#endif /* CONFIG_DEBUG_SYSLOG */

void hal_printf(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (level >= hal_debug_level) {
#ifdef CONFIG_ANDROID_LOG
		__android_log_vprint(hal_to_android_level(level), LOG_NAME,
				     fmt, ap);
#else /* CONFIG_ANDROID_LOG */
#ifdef CONFIG_DEBUG_STDOUT
		printf("%s: ", LOG_NAME);
		vprintf(fmt, ap);
		printf("\n");
#endif /* CONFIG_DEBUG_STDOUT */
#ifdef CONFIG_DEBUG_SYSLOG
		va_end(ap);
		va_start(ap, fmt);
		if (hal_debug_syslog) {
			vsyslog(syslog_priority(level), fmt, ap);
		}
#endif /* CONFIG_DEBUG_SYSLOG */
#endif /* CONFIG_ANDROID_LOG */
	}
	va_end(ap);
}
