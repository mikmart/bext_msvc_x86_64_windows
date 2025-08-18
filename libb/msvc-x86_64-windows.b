extrn printf;
extrn putchar;
extrn getchar;
extrn exit;

char __asm__(
    "xor rax, rax",
    "mov al, byte ptr [rcx + rdx]",
    "ret"
);

lchar __asm__(
    "mov byte ptr [rcx + rdx], r8b",
    "ret"
);
