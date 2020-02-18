; stub.asm - MASM test file.

.386
.model flat,stdcall
.stack 4096

.code
main proc
	pushad
	call    routine
routine :
	pop     ebp
	sub     ebp, offset routine
	push    0                                ; MB_OK
	lea     eax, [ebp + szCaption]
	push    eax                              ; lpCaption
	lea     eax, [ebp + szText]
	push    eax                              ; lpText
	push    0                                ; hWnd
	mov     eax, 0aaaaaaaah
	call    eax                              ; MessageBoxA
	popad
	push    0bbbbbbbbh                       ; OEP
	ret

szCaption:
	cap db 'Yo!', 0 
szText:
	text db 'U mind if i stay here?', 0
main endp
end main
