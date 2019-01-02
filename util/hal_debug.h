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

#ifndef HAL_DEBUG_H
#define HAL_DEBUG_H

enum {
	MSG_TRACE, MSG_DEBUG, MSG_WARNING, MSG_ERROR
};

/**
 * hal_printf - conditional printf
 * @level: priority level (MSG_*) of the message
 * @fmt: printf format string, followed by optional arguments
 *
 * This function is used to print conditional debugging and error messages. The
 * output may be directed to syslog or to Androids log, based on configuration
 */
void hal_printf(int level, const char *fmt, ...);

#ifdef CONFIG_DEBUG_SYSLOG

void hal_debug_open_syslog(void);
void hal_debug_close_syslog(void);

#else /* CONFIG_DEBUG_SYSLOG */
inline void hal_debug_open_syslog(void)
{
}

inline void hal_debug_close_syslog(void)
{
}

#endif /* CONFIG_DEBUG_SYSLOG */

#endif /* HAL_DEBUG */
