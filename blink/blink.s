; https://linuxgazette.net/issue79/sebastian.html

       list p=16f84, r=hex
#include <p16f84.inc>

f              equ     1
porta          equ     0x5             ;specify the address of the ports
portb          equ     0x6             ;
Delay_i        equ     0xc             ;The first byte of RAM available.
Long_Delay_i   equ 0xd
tmp            equ     0xe

       goto Main
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
; The following subroutine makes a 1 ms delay for a clock of 4Mhz for the PIC.
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Delay:
       movlw 0xff
       movwf Delay_i
L1:     nop
       decfsz Delay_i, f
       goto L1
       return
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;      This subroutine produces a 1 sec delay( approx.).
;
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Long_Delay:
       movwf tmp
       movlw 0xff
       movwf Long_Delay_i
L2:     call Delay
       decfsz Long_Delay_i, f
       goto L2
       movf tmp,w
       return
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;
;The following code configures all ports as output ports.
;If you want to configure a port as input port, change the
;corresponding bit to 1 in TRIS register.
;For eg.if you want to use port portb0-3 as input and all other as output
;pins, use instructions
;
;      movlw 0x0
;      tris porta
;      movlw 0x0F
;      tris portb
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
Main:
       movlw 0x0
       tris porta
       tris portb

       movlw 0xff
       movwf portb
L3:
       call Long_Delay         ;make a 1 sec delay between blinking.
       comf portb,f            ;complement portb
       goto L3

       end
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


