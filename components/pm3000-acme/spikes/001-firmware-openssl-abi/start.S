.section .text
.globl _start
.type _start,@function
_start:
    bl main
    li 0,1
    sc
.size _start,.-_start
.section .note.GNU-stack,"",@progbits
