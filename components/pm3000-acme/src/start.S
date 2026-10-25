.section .text
.globl _start
.type _start,@function
_start:
    lwz 3,0(1)
    addi 4,1,4
    bl main
    li 0,1
    sc
    b .
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
