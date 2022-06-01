#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"

#define F (1 << 14) //fixed point 1
#define INT_MAX ((1 << 31) - 1)
#define INT_MIN (-(1 << 31))

// x and y denote fixed_point numbers in 17.14 format
// n is an integer
int int_to_fp(int n); /* integer를 fixed point로 전환 */
int fp_to_int_round(int x); /* FP를 int로 전환(반올림) */
int fp_to_int(int x); /* FP를 int로 전환(버림) */
int add_fp(int x, int y); /* FP의 덧셈 */
int add_mixed(int x, int n); /* FP와 int의 덧셈 */
int sub_fp(int x, int y); /* FP의 뺄셈(x-y) */
int sub_mixed(int x, int n); /* FP와 int의 뺄셈(x-n) */
int mult_fp(int x, int y); /* FP의 곱셈 */
int mult_mixed(int x, int y); /* FP와 int의 곱셈 */
int div_fp(int x, int y); /* FP의 나눗셈(x/y) */
int div_mixed(int x, int n); /* FP와 int 나눗셈(x/n) */

#define F (1 << 14) // fixed point 1: 0 00000000000000001 00000000000000
                    // 1 bit(sign), 17 bit(정수부), 14 bit(소수부)
                    // sign이 0이면 양수, 1이면 음수
#define INT_MAX ((1 << 31) - 1) // 0 11111111111111111 11111111111111
#define INT_MIN (-(1 << 31))    // 1 00000000000000000 00000000000000

/* 
    만약 recent_cpu 가 2.75 라는 값을 가진다면
    [0 00000000000000010 11000000000000] (소수부의 각 비트는 2^(-1), 2^(-2), ... ) 
    = 45056
*/

/* 
    x, y: fixed point
    n: int
*/

/* integer를 fixed point로 전환 */
int int_to_fp(int n) {
    return n * F;
    // return n * 2^14;
} 

/* FP를 int로 전환(반올림) */
int fp_to_int_round(int x) {
    if (x >= 0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
    // return (int)floor((x / 2^14) + 0.5);
} 

/* FP를 int로 전환(버림) */
int fp_to_int(int x) {
    return x / F;
    // return (int)floor(x / 2^14);
}

/* FP의 덧셈 */
int add_fp(int x, int y) {
    return x + y;
}

/* FP와 int의 덧셈 */
int add_mixed(int x, int n) {
    return x + n * F;
}

/* FP의 뺄셈(x-y) */
int sub_fp(int x, int y) {
    return x - y;
}

/* FP와 int의 뺄셈(x-n) */
int sub_mixed(int x, int n) {
    return x - n * F;
}

/* FP의 곱셈 */
int mult_fp(int x, int y) {
    return ((int64_t) x) * y / F; // 두 개의 fp 를 곱하면 32bit * 32bit 로 32bit 를 초과하는 값이 발생하기 때문에 x 를 64bit 로 일시적으로 바꿔준 후 곱하기 연산을 하여 오버플로우를 방지하고 계산 결과로 나온 64bit 값을 F 로 나눠서 다시 32bit 값으로 만들어 줌
}

/* FP와 int의 곱셈 */
int mult_mixed(int x, int n) {
    return x * n;
}

/* FP의 나눗셈(x/y) */
int div_fp(int x, int y) {
    return ((int64_t)x) * F / y;
}

/* FP와 int 나눗셈(x/n) */
int div_mixed(int x, int n) {
    return x / n;
}