  .thumb
  .syntax unified
.text

/*************************************************
* Barrett reduction
* - a: register to be reduced
* - tmp: temporary register
* - q: register containing q
**************************************************/
.macro barrett_reduce_asm a, tmp, q
  lsr \tmp, \a, #13    // tmp = a>>13
  mls \a, \tmp, \q, \a // a -= tmp * q
.endm

/*************************************************
* Montgomery reduction
* - a: register to be reduced
* - tmp: temporary register
* - q: register containing q
* - qinv: register containing qinv = -inverse_mod(q,2^18)
* - mask: register containing (1<<18)-1
**************************************************/
.macro montgomery_reduce_asm a, tmp, q, qinv, mask
  mul \tmp, \a, \qinv  // tmp = (a * qinv)
  and \tmp, \mask      // tmp &= mask
  mla \a, \tmp, \q, \a // a += tmp * q
  lsr \a, #18          // a = a>>18
.endm

/*************************************************
* Pointwise add (a,b) => r = barrett_reduce(a+b)
* - r0: pointer to r
* - r1: pointer to a
* - r2: pointer to b
**************************************************/
.align 4
.global pointwise_add
.type pointwise_add, %function
pointwise_add:
  push    {r3 - r12, lr}

  /// store parameters in registers ///
  movw r12, #0x1e01 // r12 = q = 7681
  movw r11, #7
  movt r11, #7      // r11 = 0x70007

  /// counter in register 14 ///
  mov r14, #32

  /// main loop: do 8 by 8 ///
1: 
  ldm r1!, {r3, r5, r7, r9}
  ldm r2!, {r4, r6, r8, r10}
  add r3, r4
  add r5, r6
  add r7, r8
  add r9, r10
  lsr r4, r3, #13
  lsr r6, r5, #13
  lsr r8, r7, #13
  lsr r10, r9, #13
  and r4, r11
  and r6, r11
  and r8, r11
  and r10, r11
  mls r3, r4, r12, r3
  mls r5, r6, r12, r5
  mls r7, r8, r12, r7
  mls r9, r10, r12, r9
  stm r0!, {r3, r5, r7, r9}
  subs r14, #1
  bne 1b

  pop    {r3 - r12, pc}

/*************************************************
* Pointwise sub (a,b) => r = barrett_reduce(3q+a-b)
* - r0: pointer to r
* - r1: pointer to a
* - r2: pointer to b
**************************************************/
.align 4
.global pointwise_sub
.type pointwise_sub, %function
pointwise_sub:
  push    {r3 - r12, lr}

  /// store parameters in registers ///
  movw r12, #0x5a03 
  movt r12, #0x5a03 // 3q on both halfwords
  movw r11, #7
  movt r11, #7      // r11 = 0x70007
  movw r10, #0x1e01 // r10 = q = 7681

  /// counter in register 14 ///
  mov r14, #64

  /// main loop: do 4 by 4 ///
1:
  ldm r1!, {r3, r5}
  ldm r2!, {r4, r6}
  add r3, r12
  add r5, r12
  sub r3, r4
  sub r5, r6
  lsr r4, r3, #13
  lsr r6, r5, #13
  and r4, r11
  and r6, r11
  mls r3, r4, r10, r3
  mls r5, r6, r10, r5
  stm r0!, {r3, r5}
  subs r14, #1
  bne 1b

  pop    {r3 - r12, pc}
