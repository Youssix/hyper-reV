# HyperREV Development Rules

## Incremental Debugging (MANDATORY)
When implementing or debugging any new feature — especially EPT hooks, shadow pages, or kernel-level mechanisms:
1. **Start with the simplest possible test** — e.g., a JMP that immediately jumps back (NOP hook). Verify it doesn't crash.
2. **Verify each layer independently** before combining:
   - Does the EPT split work? (shadow page exists, execute redirects)
   - Do ALL processes see the shadow page? (kernel .text is global)
   - Does the trampoline jump back correctly?
   - Only THEN add actual hook logic
3. **Never skip validation steps** — if step N hasn't been tested, don't build step N+1 on top of it.
4. **One variable at a time** — don't change multiple things between tests.

## Serial Logging Rules
- **Boot/init logs**: OK (run once, low overhead)
- **VMEXIT hot path**: NEVER put serial::print or _InterlockedIncrement counters on every VMEXIT. This causes system freeze/BSOD (VIDEO_SCHEDULER_INTERNAL_ERROR from GPU timeout).
- **Rare events only**: Log first N occurrences, or log on hypercall-triggered queries.
- **Counters**: Plain `++` is fine (no interlocked needed for approximate counts). Query via CPUID hypercall from usermode.

## Code Preservation
- **NEVER delete code during bisect/debugging** — always comment it out (`/* */` or `//`)
- User wants original code visible as comments, not replaced

## Build
- `cmd.exe //c "D:\\Games\\HyperREV\\hyper-reV\\build_phase3.bat"`
- Must use cmd.exe, not bash directly
