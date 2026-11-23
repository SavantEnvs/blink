// Guest program for mayhem/test.sh's filesystem-jail check: creates
// /tmp/blink-jail-probe (O_CREAT|O_WRONLY, 0600), prints "created" and exits
// 0 if the open succeeded, exits 1 otherwise. Under the fuzz front end the
// file must land in the per-run jail, never in the host's /tmp.
// Build: gcc -nostdlib -static -Wl,--build-id=none -o jail-elf jail.S
	.globl	_start
	.text
_start:	mov	$2,%eax			// open
	lea	path(%rip),%rdi
	mov	$0101,%esi		// O_CREAT|O_WRONLY
	mov	$0600,%edx
	syscall
	test	%rax,%rax
	js	fail
	mov	$1,%eax			// write(1, msg, len)
	mov	$1,%edi
	lea	msg(%rip),%rsi
	mov	$len,%edx
	syscall
	xor	%edi,%edi
	jmp	done
fail:	mov	$1,%edi
done:	mov	$60,%eax		// exit
	syscall
path:	.asciz	"/tmp/blink-jail-probe"
msg:	.ascii	"created\n"
	len = . - msg
