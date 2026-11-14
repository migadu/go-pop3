//go:build arm64 && !purego && !pop3scalar

#include "textflag.h"

TEXT ·ordinaryPrefixVector(SB), NOSPLIT, $0-32
	MOVD p_base+0(FP), R0
	MOVD p_len+8(FP), R1
	MOVD $1, R2
	MOVD $10, R3
	VMOV R3, V0.B16
	MOVD $13, R3
	VMOV R3, V1.B16
	MOVD $46, R3
	VMOV R3, V2.B16
	MOVD $-1, R3
	VMOV R3, V8.B16
// Check 16 current bytes against their 16 preceding bytes.
loop:
	SUB R2, R1, R3
	CMP $16, R3
	BLT done
	ADD R2, R0, R4
	SUB $1, R4, R5
	VLD1 (R4), [V3.B16]
	VLD1 (R5), [V4.B16]
	// Bare LF: current == LF and previous != CR.
	VCMEQ V0.B16, V3.B16, V5.B16
	VCMEQ V1.B16, V4.B16, V6.B16
	VEOR V8.B16, V6.B16, V6.B16
	VAND V6.B16, V5.B16, V5.B16
	// Stuffed dot: current == dot and previous == LF.
	VCMEQ V2.B16, V3.B16, V6.B16
	VCMEQ V0.B16, V4.B16, V7.B16
	VAND V6.B16, V7.B16, V7.B16
	VORR V5.B16, V7.B16, V7.B16
	VMOV V7.D[0], R6
	VMOV V7.D[1], R7
	ORR R6, R7, R6
	CBNZ R6, done
	ADD $16, R2
	B loop
done:
	// Retain the previous byte so scalar scanning sees a boundary LF/dot.
	SUB $1, R2
	MOVD R2, ret+24(FP)
	RET
