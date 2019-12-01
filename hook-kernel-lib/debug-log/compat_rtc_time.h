
#ifndef  _COMPAT_RTC_TIME_H
#define  _COMPAT_RTC_TIME_H

#include <linux/rtc.h>


#include <linux/version.h>

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18) || !defined(CONFIG_RTC_LIB)

int rtc_month_days(unsigned int month, unsigned int year);

void rtc_time_to_tm(unsigned long time, struct rtc_time *tm);

#endif


#endif //_COMPAT_RTC_TIME_H
