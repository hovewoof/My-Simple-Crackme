#ifndef ANTIDISASSM_H
#define ANTIDISASSM_H

VOID AntiDisassmConstantCondition();
VOID AntiDisassmAsmJmpSameTarget();
VOID AntiDisassmImpossibleDisassm();
VOID AntiDisassmFunctionPointer();
VOID AntiDisassmReturnPointerAbuse();
VOID AntiDisassmSEHMisuse();

#endif //ANTIDISASSM_H