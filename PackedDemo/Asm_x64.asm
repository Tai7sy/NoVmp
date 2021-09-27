
.CODE

func_call_dummy proc
	mov eax, ecx
	ret
func_call_dummy endp

func_call proc
	mov ecx, 1
	call func_call_dummy
	ret
func_call endp

func_loop proc
	mov eax, 0

	LOOP_BEGIN:
	cmp eax, 2
	jg LOOP_END
	inc eax
	jmp LOOP_BEGIN

	LOOP_END:
	ret
func_loop endp

func1 proc
	mov eax, 1111h
	mov ebx, 2222h
	ret
func1 endp

func2 proc
	mov eax, 1111h
	add eax, 2222h
	ret
func2 endp

func3 proc
	mov eax, 1111h
	mov ebx, 2
	mul ebx
	ret
func3 endp

func4 proc
	mov eax, 1111h
	shl eax, 18h
	ret
func4 endp

func5 proc
	mov eax, 1111h
	rol eax, 18h
	ret
func5 endp

END