// Disable LeakSanitizer at build time (leaks are not the bug class we fuzz for).
int __lsan_is_turned_off(void) { return 1; }
