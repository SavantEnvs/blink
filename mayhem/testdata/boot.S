	.code16
	.globl _start
	.text
_start:	cli
	xor	%ax,%ax
	mov	%ax,%ds
	mov	$0x0e48,%ax
	int	$0x10
	mov	$0x0e49,%ax
	int	$0x10
	lgdt	gdtr - _start + 0x7c00
	sgdt	gdts - _start + 0x7c00
	mov	%cr0,%eax
	or	$1,%al
	mov	%eax,%cr0
	ljmp	$0x08,$(pm - _start + 0x7c00)
	.code32
pm:	mov	$0x10,%ax
	mov	%ax,%ds
	mov	%ax,%es
	mov	$0x10,%ebx
	lsl	%ebx,%ecx
	mov	$0x18,%ax
	mov	%ax,%fs
	hlt
	.p2align 3
gdt:	.quad	0
	.quad	0x00cf9a000000ffff
	.quad	0x00cf92000000ffff
gdtr:	.word	gdtr - gdt - 1
	.long	gdt - _start + 0x7c00
gdts:	.word	0
	.long	0
	.org	510
	.byte	0x55,0xaa
