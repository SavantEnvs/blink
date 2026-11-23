	.globl _start
	.text
_start:	mov	$1,%eax
	mov	$1,%edi
	lea	msg(%rip),%rsi
	mov	$len,%edx
	syscall
	mov	$7,%ecx
	imul	$6,%ecx,%edi
	mov	$60,%eax
	syscall
msg:	.ascii	"hello from blink\n"
	len = . - msg
