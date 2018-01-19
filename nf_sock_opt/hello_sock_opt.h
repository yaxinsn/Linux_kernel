/*
上下通信的通用头文件。

*/


#define  HELLO_BASE_CTL  102400 //在系统中这个号不能有重复的。建议最好是取较大值。
#define  HELLO_LISA      HELLO_BASE_CTL+1
#define  HELLO_MONA      HELLO_BASE_CTL+2
#define  HELLO_SO_SET_MAX  (HELLO_BASE_CTL+5)
