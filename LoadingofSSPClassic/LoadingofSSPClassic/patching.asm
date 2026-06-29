; Return address patching
; ChangeRetAddress( PVOID Function, SIZE_T nArgs, PVOID gadget, ... )

.code

PUBLIC ChangeRetAddress

ChangeRetAddress PROC
	sub     rsp, 100h

	mov     qword ptr [rsp+8h], rsi
	mov     qword ptr [rsp+10h], rdi
	mov     qword ptr [rsp+18h], r12

	mov     r10, rcx
	lea     r12, Fixup_Label
	lea     rbx, Fixup_Label

	sub     rsp, 200h

	mov     qword ptr [rsp], r8

	cmp     rdx, 0
	je      Forward_Call

	mov     r11, rdx

	mov     rcx, r9
	mov     rdx, qword ptr [rsp+300h+28h]
	mov     r8,  qword ptr [rsp+300h+30h]
	mov     r9,  qword ptr [rsp+300h+38h]

	cmp     r11, 4
	jle     Forward_Call

	mov     rax, rcx
	mov     rcx, r11
	sub     rcx, 4
	lea     rsi, [rsp+28h+18h+300h]
	lea     rdi, [rsp+28h]
	rep     movsq
	mov     rcx, rax

Forward_Call:
	jmp     r10

Fixup_Label:
	mov     rsi, qword ptr [rsp+200h+8h]
	mov     rdi, qword ptr [rsp+200h+10h]
	mov     r12, qword ptr [rsp+200h+18h]
	add     rsp, 300h
	ret

ChangeRetAddress ENDP

END
