.syntax unified
.cpu cortex-m4
.thumb

/* result in upper half word of tmp */
.macro montgomery q,qinv,a,tmp
  smulbb \tmp,\a,\qinv
  smulbb \tmp,\tmp,\q
  usub16 \tmp,\a,\tmp
.endm  

.macro barrett a,tmp,q
  asr \tmp,\a,#13    // tmp = a>>13
  mls \a, \tmp,\q,\a // a -= tmp * q
.endm

.macro doublebarrett a,tmp,tmp2,q
  asr \tmp,\a,#29
  mul \tmp, \tmp,\q  
  sxth \tmp2,\a 
  asr \tmp2,\tmp2,#13 
  mul \tmp2,\tmp2,\q
  pkhbt \tmp,\tmp2,\tmp,lsl#16 
  usub16 \a,\a,\tmp
.endm

.macro barrett2 a, tmp, q
  asr  \tmp,\a,#15
  and  \tmp,\tmp,\q,lsl#1
  add.w  \a,\a,\q
  add.w  \a,\a,\tmp
.endm

 
.macro butterfly_nobarrett tb, a0, a1, twiddle, tmp, q, qinv 
  smulb\tb \a1, \a1, \twiddle
  montgomery \q, \qinv, \a1, \tmp
  sasx \a1,\a0,\tmp
  ssax \a0,\a0,\tmp
.endm 

.macro doublebutterfly_nobarrett tb, a0, a1, twiddle, tmp, tmp2, q, qinv
  smulb\tb \tmp, \a1, \twiddle
  smult\tb \a1, \a1, \twiddle
  montgomery \q, \qinv, \tmp, \tmp2
  montgomery \q, \qinv, \a1, \tmp
  pkhtb \tmp2, \tmp, \tmp2, asr#16
  usub16 \a1,\a0,\tmp2
  uadd16 \a0,\a0,\tmp2
.endm

.macro butterfly_barrett tb, a0, a1, twiddle, tmp, q, qinv
  barrett \a0,\tmp,\q 
  butterfly_nobarrett \tb, \a0, \a1, \twiddle, \tmp, \q, \qinv 
.endm 

.macro doublebutterfly_barrett tb, a0, a1, twiddle, tmp, tmp2, q, qinv
  doublebarrett \a0, \tmp, \tmp2, \q
  doublebutterfly_nobarrett  \tb, \a0, \a1, \twiddle, \tmp, \tmp2, \q, \qinv
.endm

.macro butterfly_barrett2 tb, a0, a1, twiddle, tmp, q, qinv
  barrett2 \a0,\tmp,\q 
  butterfly_nobarrett \tb, \a0, \a1, \twiddle, \tmp, \q, \qinv 
.endm 

.global ntt_fast
.type ntt_fast, %function
.align 2
ntt_fast:
  push {r4-r11, r14}

  poly        .req r0
  twiddle_ptr .req r1
  loopctr     .req r2
  poly0       .req r3
  poly1       .req r4
  poly2       .req r5
  poly3       .req r6
  twiddle2    .req r7
  tmp3        .req r8
  tmp2        .req r9
  tmp         .req r10
  twiddle     .req r11   
  qinv        .req r12
  q           .req r14

  mov q, #7681
  mov qinv, #57857

  ### LAYER 7+6
  mov loopctr, #32
  ldrh twiddle, [twiddle_ptr], #2
  ldr twiddle2, [twiddle_ptr], #4
  layer7_6: 
    ldr.w poly0, [poly]
    ldr.w poly1, [poly, #128]
    ldr.w poly2, [poly, #256]     
    ldr.w poly3, [poly, #384]     

    doublebutterfly_nobarrett b, poly0, poly2, twiddle, tmp, tmp2, q, qinv
    doublebutterfly_nobarrett b, poly1, poly3, twiddle, tmp, tmp2, q, qinv
    doublebutterfly_nobarrett b, poly0, poly1, twiddle2, tmp, tmp2, q, qinv
    doublebutterfly_nobarrett t, poly2, poly3, twiddle2, tmp, tmp2, q, qinv
     
    str.w poly1, [poly, #128]     
    str.w poly2, [poly, #256]     
    str.w poly3, [poly, #384]     
    str.w poly0, [poly], #4

  subs.w loopctr, #1
  bne.w layer7_6

  sub.w poly, #128
  
  ### LAYER 5+4
  .rept 4
    mov loopctr, #8
    ldrh twiddle, [twiddle_ptr], #2
    ldr twiddle2, [twiddle_ptr], #4
    1: 
      ldr.w poly0, [poly]
      ldr.w poly1, [poly, #32]
      ldr.w poly2, [poly, #64]
      ldr.w poly3, [poly, #96]
      
      doublebutterfly_nobarrett b, poly0, poly2, twiddle, tmp,tmp2, q, qinv
      doublebutterfly_nobarrett b, poly1, poly3, twiddle, tmp,tmp2, q, qinv     

      doublebutterfly_barrett   b, poly0, poly1, twiddle2, tmp,tmp2 q, qinv
      doublebutterfly_barrett   t, poly2, poly3, twiddle2, tmp,tmp2, q, qinv
     
      str.w poly1, [poly, #32]     
      str.w poly2, [poly, #64]     
      str.w poly3, [poly, #96]     
      str.w poly0, [poly], #4
    subs.w loopctr, #1
    bne.w 1b
  add.w poly, #96
  .endr
 
  sub.w poly, #512
  
  ### LAYER 3+2
  mov loopctr, #16
  layer3_out:
    ldrh twiddle, [twiddle_ptr], #2
    ldr twiddle2, [twiddle_ptr], #4

    .rept 2
      ldr.w poly0, [poly]
      ldr.w poly1, [poly, #8]
      ldr.w poly2, [poly, #16]
      ldr.w poly3, [poly, #24]
      
      doublebutterfly_nobarrett b, poly0, poly2, twiddle, tmp, tmp2, q, qinv
      doublebutterfly_nobarrett b, poly1, poly3, twiddle, tmp, tmp2, q, qinv
      doublebutterfly_nobarrett b, poly0, poly1, twiddle2, tmp, tmp2, q, qinv
      doublebutterfly_nobarrett t, poly2, poly3, twiddle2, tmp, tmp2, q, qinv
     
      str.w poly1, [poly, #8]     
      str.w poly2, [poly, #16]     
      str.w poly3, [poly, #24]     
      str.w poly0, [poly], #4
      .endr
  add.w poly, #24
  subs.w loopctr, #1
  bne.w layer3_out 

  sub poly, #512
  ### LAYER 1+0
  mov loopctr, #64
  layer1_out:
    ldrh twiddle, [twiddle_ptr], #2
    ldr twiddle2, [twiddle_ptr], #4
    ldrsh poly0, [poly]
    ldrsh poly1, [poly, #2]
    ldrsh poly2, [poly, #4]
    ldrsh poly3, [poly, #6]

    butterfly_barrett b, poly0, poly2, twiddle, tmp, q, qinv
    butterfly_barrett b, poly1, poly3, twiddle, tmp, q, qinv
  
    sxth poly0, poly0
    sxth poly2, poly2
    
    butterfly_barrett2 b, poly0, poly1, twiddle2, tmp, q, qinv
    butterfly_barrett2 t, poly2, poly3, twiddle2, tmp, q, qinv
    
    strh.w poly1, [poly, #2]     
    strh.w poly2, [poly, #4]     
    strh.w poly3, [poly, #6]     
    strh.w poly0, [poly], #8
    subs.w loopctr, #1
    bne.w layer1_out 
  pop {r4-r11, pc}
  
.macro barrett3 a, tmp, q, barrettconst
  smulbt \tmp, \a, \barrettconst
  asr \tmp, \tmp, #27
  mls \a, \tmp, \q, \a 
.endm

.macro invbutterfly_nobarrett tb, a0, a1, twiddle, tmp, q, qinv 
  usub16 \tmp, \a0, \a1
  uadd16 \a0, \a0, \a1
  smulb\tb \a1, \tmp, \twiddle
  montgomery \q, \qinv, \a1, \tmp
  asr \a1, \tmp, #16
.endm 

.macro doubleinvbutterfly_nobarrett tb, a0, a1, twiddle, tmp, tmp2, q, qinv
  usub16 \tmp, \a0, \a1
  uadd16 \a0, \a0, \a1

  smulb\tb \a1, \tmp, \twiddle
  smult\tb \tmp, \tmp, \twiddle
  # result in tmp2
  montgomery \q, \qinv, \a1, \tmp2
  # result in a1
  montgomery \q, \qinv, \tmp, \a1 
  pkhtb \a1, \a1, \tmp2, asr#16
.endm

.macro invbutterfly_barrett3 tb, a0, a1, twiddle, tmp, q, qinv, barrettconst
  invbutterfly_nobarrett \tb, \a0, \a1, \twiddle, \tmp, \q, \qinv
  barrett3 \a0,\tmp,\q,\barrettconst
.endm

.macro doublebarrett3 a, tmp,tmp2, q, barrettconst
  smulbt \tmp, \a, \barrettconst
  smultt \tmp2, \a, \barrettconst
  asr \tmp, \tmp, #27
  asr \tmp2, \tmp2, #27
  smulbb \tmp, \tmp, \q
  smulbb \tmp2, \tmp2, \q 
  pkhbt \tmp, \tmp, \tmp2, lsl#16
  usub16 \a, \a, \tmp
.endm
.macro doubleinvbutterfly_barrett3 tb, a0, a1, twiddle, tmp, tmp2, q, qinv, barrettconst
  usub16 \tmp, \a0, \a1
  uadd16 \a0, \a0, \a1

  smulb\tb \a1, \tmp, \twiddle
  smult\tb \tmp, \tmp, \twiddle
  # result in tmp2
  montgomery \q, \qinv, \a1, \tmp2
  # result in a1
  montgomery \q, \qinv, \tmp, \a1 
 
  pkhtb \a1, \a1, \tmp2, asr#16
  doublebarrett3 \a0, \tmp, \tmp2, \q, \barrettconst

.endm
.macro invbutterfly_layer7 tb, poly0, poly1, twiddle, tmp, q, qinv, barrettconst
    invbutterfly_barrett3 \tb, \poly0, \poly1, \twiddle, \tmp, \q, \qinv, \barrettconst    
    sxth.w \poly0, \poly0 
    lsl \poly0, #8 
    montgomery \q, \qinv, \poly0, \tmp
    add \poly0, \q, \tmp, asr#16
    add.w \poly1, \q
.endm

.macro doubleinvbutterfly_layer7 tb, poly0, poly1, twiddle, tmp,tmp2, q, qinv, barrettconst, c256
  usub16 \tmp, \poly0, \poly1
  uadd16 \poly0, \poly0, \poly1

  smulb\tb \poly1, \tmp, \twiddle
  smult\tb \tmp, \tmp, \twiddle
  # result in tmp2
  montgomery \q, \qinv, \poly1, \tmp2
  # result in poly1
  montgomery \q, \qinv, \tmp, \poly1 
 
  pkhtb \poly1, \poly1, \tmp2, asr#16
  uadd16 \poly1, \poly1, \q
  
  sxth \tmp2, \poly0
  lsl \tmp2, #8 
  montgomery \q, \qinv, \tmp2, \tmp

  smultb \poly0, \poly0, \c256
  montgomery \q, \qinv, \poly0, \tmp2

  pkhtb \poly0, \tmp2, \tmp, asr#16
  uadd16 \poly0, \poly0, \q
.endm

.global invntt_fast
.type invntt_fast, %function
.align 2
invntt_fast:
  push {r4-r11, lr}
  
  poly                .req r0
  twiddle_ptr         .req r1
  loopctr             .req r2
  poly0               .req r3
  poly1               .req r4
  poly2               .req r5
  poly3               .req r6
  twiddle2            .req r7
  tmp3                .req r8
  tmp2                .req r9
  tmp                 .req r10
  twiddle             .req r11   
  qinv                .req r12
  barrettconst        .req r12
  q                   .req r14
 
  mov  q, #7681
  movt q, #7681
  # contains qinv in lower halfword, and 17474 in upper halfword (constant used in barrett3)
  mov  qinv, #57857
  movt barrettconst, #17474 
  ### LAYER 0+1 
  mov loopctr, #64
  invlayer0:
    ldr twiddle, [twiddle_ptr], #4
    ldrh twiddle2, [twiddle_ptr], #2

    ldrsh poly0, [poly]
    ldrsh poly1, [poly, #2]
    ldrsh poly2, [poly, #4]
    ldrsh poly3, [poly, #6]
    
    invbutterfly_nobarrett b, poly0, poly1, twiddle, tmp, q, qinv
    invbutterfly_nobarrett t, poly2, poly3, twiddle, tmp, q, qinv

    invbutterfly_barrett3 b, poly0, poly2, twiddle2, tmp, q, qinv, barrettconst
    invbutterfly_barrett3 b, poly1, poly3, twiddle2, tmp, q, qinv, barrettconst

    strh.w poly1, [poly, #2]
    strh.w poly2, [poly, #4]
    strh.w poly3, [poly, #6]
    strh.w poly0, [poly], #8   
    subs.w loopctr, #1
    bne.w invlayer0
  sub poly, #512
  
 
  ### LAYER 2+3
  mov loopctr, #16
  invlayer2_out:
    ldr twiddle, [twiddle_ptr], #4
    ldrh twiddle2, [twiddle_ptr], #2

    .rept 2
      ldr poly0, [poly]
      ldr poly1, [poly, #8]
      ldr poly2, [poly, #16]
      ldr poly3, [poly, #24]
      
      doubleinvbutterfly_nobarrett b, poly0, poly1, twiddle, tmp, tmp2, q, qinv
      doubleinvbutterfly_nobarrett t, poly2, poly3, twiddle, tmp, tmp2, q, qinv

      doubleinvbutterfly_barrett3 b, poly0, poly2, twiddle2, tmp, tmp2, q, qinv, barrettconst
      doubleinvbutterfly_barrett3 b, poly1, poly3, twiddle2, tmp, tmp2, q, qinv, barrettconst
     
      str.w poly1, [poly, #8]
      str.w poly2, [poly, #16]
      str.w poly3, [poly, #24]
      str.w poly0, [poly], #4
    .endr
    add poly, #24
  subs.w loopctr, #1
  bne.w invlayer2_out 
  sub poly, #512
  ### LAYER 4+5
  .rept 4
      ldr twiddle, [twiddle_ptr], #4
      ldrh twiddle2, [twiddle_ptr], #2
      mov loopctr, #8
      51:
          ldr poly0, [poly]
          ldr poly1, [poly, #32]
          ldr poly2, [poly, #64]
          ldr poly3, [poly, #96]
  
          doubleinvbutterfly_nobarrett b, poly0, poly1, twiddle, tmp, tmp2, q, qinv
          doubleinvbutterfly_nobarrett t, poly2, poly3, twiddle, tmp, tmp2, q, qinv
          # be lazy here - only first half needs the barrett reduction
          doubleinvbutterfly_barrett3 b, poly0, poly2, twiddle2, tmp, tmp2, q, qinv, barrettconst
          doubleinvbutterfly_nobarrett b, poly1, poly3, twiddle2, tmp, tmp2,  q, qinv
      
          str.w poly1, [poly, #32]
          str.w poly2, [poly, #64]
          str.w poly3, [poly, #96]
          str.w poly0, [poly], #4

        subs.w loopctr, #1
      bne.w 51b
      add poly, #96
  .endr

  mov tmp3, #256
  sub poly, #512
  ### LAYER 6+7
  ldr twiddle, [twiddle_ptr], #4
  ldrh twiddle2, [twiddle_ptr], #2
  # be lazy here - only second quarter needs the barrett reduction
  mov loopctr, #8
  61:
    ldr.w poly0, [poly]
    ldr.w poly1, [poly, #128]
    ldr.w poly2, [poly, #256]
    ldr.w poly3, [poly, #384]
 
    doubleinvbutterfly_nobarrett b, poly0, poly1, twiddle, tmp,tmp2, q, qinv
    doubleinvbutterfly_nobarrett t, poly2, poly3, twiddle, tmp,tmp2, q, qinv
    doubleinvbutterfly_layer7 b, poly0, poly2, twiddle2, tmp,tmp2, q, qinv, barrettconst, tmp3
    doubleinvbutterfly_layer7 b, poly1, poly3, twiddle2, tmp,tmp2, q, qinv, barrettconst, tmp3
    
    str.w poly1, [poly, #128]
    str.w poly2, [poly, #256]
    str.w poly3, [poly, #384]
    str.w poly0, [poly], #4
 
  subs.w loopctr, #1
  bne.w 61b
    
  mov loopctr, #8
  62:
    ldr.w poly0, [poly]
    ldr.w poly1, [poly, #128]
    ldr.w poly2, [poly, #256]
    ldr.w poly3, [poly, #384]
 
    doubleinvbutterfly_barrett3 b, poly0, poly1, twiddle, tmp, tmp2, q, qinv, barrettconst
    doubleinvbutterfly_barrett3 t, poly2, poly3, twiddle, tmp, tmp2, q, qinv, barrettconst
    doubleinvbutterfly_layer7 b, poly0, poly2, twiddle2, tmp, tmp2, q, qinv, barrettconst,tmp3
    doubleinvbutterfly_layer7 b, poly1, poly3, twiddle2, tmp, tmp2, q, qinv, barrettconst,tmp3
    
    str.w poly1, [poly, #128]
    str.w poly2, [poly, #256]
    str.w poly3, [poly, #384]
    str.w poly0, [poly], #4
 
  subs.w loopctr, #1
  bne.w 62b
    
  mov loopctr, #16
  63:
    ldr.w poly0, [poly]
    ldr.w poly1, [poly, #128]
    ldr.w poly2, [poly, #256]
    ldr.w poly3, [poly, #384]
 
    doubleinvbutterfly_nobarrett b, poly0, poly1, twiddle, tmp, tmp2, q, qinv
    doubleinvbutterfly_nobarrett t, poly2, poly3, twiddle, tmp, tmp2, q, qinv
    doubleinvbutterfly_layer7 b, poly0, poly2, twiddle2, tmp, tmp2, q, qinv, barrettconst,tmp3
    doubleinvbutterfly_layer7 b, poly1, poly3, twiddle2, tmp, tmp2, q, qinv, barrettconst,tmp3
    
    str.w poly1, [poly, #128]
    str.w poly2, [poly, #256]
    str.w poly3, [poly, #384]
    str.w poly0, [poly], #4
 
  subs.w loopctr, #1
  bne.w 63b
  pop {r4-r11, pc}

