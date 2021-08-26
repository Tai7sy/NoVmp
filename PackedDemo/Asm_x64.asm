
.CODE


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
	shl eax, 16
	ret
func4 endp


END