import type {
  CapstoneFactory,
  CapstoneHandle,
  CapstoneInstruction,
  CapstoneModule,
  CapstoneOperand,
} from "@alexaltea/capstone-js";

import {
  DisassemblyBackendError,
  type ArmDisassemblyBackend,
  type ArmMode,
  type DecodedArmInstruction,
  type DecodedArmOperand,
  type DecodedArmPcRelativeSemantics,
} from "./backend.js";

let modulePromise: Promise<CapstoneModule> | null = null;

async function loadCapstone(): Promise<CapstoneModule> {
  if (modulePromise === null) {
    modulePromise = import("@alexaltea/capstone-js")
      .then(async (loaded) => await (loaded.default as CapstoneFactory)())
      .catch((error: unknown) => {
        modulePromise = null;
        throw new DisassemblyBackendError(
          `Unable to initialize Capstone.js: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      });
  }
  return await modulePromise;
}

function hasGroup(instruction: CapstoneInstruction, group: number): boolean {
  return instruction.detail.groups?.includes(group) === true;
}

function isKnownJumpInstruction(cs: CapstoneModule, id: number): boolean {
  return id === cs.ARM_INS_B
    || id === cs.ARM_INS_BX
    || id === cs.ARM_INS_BXJ
    || id === cs.ARM_INS_BXNS
    || id === cs.ARM_INS_CBZ
    || id === cs.ARM_INS_CBNZ;
}

function isKnownCallInstruction(cs: CapstoneModule, id: number): boolean {
  return id === cs.ARM_INS_BL
    || id === cs.ARM_INS_BLX
    || id === cs.ARM_INS_BLXNS;
}

function registerName(
  decoder: CapstoneHandle,
  registerId: number | undefined,
): string | null {
  if (registerId === undefined || registerId === 0) {
    return null;
  }
  const name = decoder.reg_name(registerId).toLowerCase();
  return name.length === 0 ? null : name;
}

function normalizeOperand(
  cs: CapstoneModule,
  decoder: CapstoneHandle,
  operand: CapstoneOperand,
): DecodedArmOperand {
  if (operand.type === cs.ARM_OP_IMM && operand.imm !== undefined) {
    return { kind: "immediate", value: operand.imm >>> 0 };
  }
  if (operand.type === cs.ARM_OP_REG && operand.reg !== undefined) {
    return {
      kind: "register",
      name: decoder.reg_name(operand.reg).toLowerCase(),
    };
  }
  if (operand.type === cs.ARM_OP_MEM && operand.mem !== undefined) {
    return {
      kind: "memory",
      value: {
        baseRegister: registerName(decoder, operand.mem.base),
        indexRegister: registerName(decoder, operand.mem.index),
        displacement: operand.mem.disp ?? 0,
      },
    };
  }
  return { kind: "other" };
}

const CONTROL_FLOW_REGISTER = /^(?:r(?:1[0-5]|[0-9])|sp|lr|pc|ip|fp|sl|sb)$/u;

function normalizeControlFlowOperands(
  cs: CapstoneModule,
  instruction: CapstoneInstruction,
  operands: readonly DecodedArmOperand[],
): readonly DecodedArmOperand[] {
  if (operands.length > 0) {
    return operands;
  }

  const register = instruction.op_str.trim().toLowerCase();
  if (!CONTROL_FLOW_REGISTER.test(register)) {
    return operands;
  }

  const registerControlFlow = instruction.id === cs.ARM_INS_BX
    || instruction.id === cs.ARM_INS_BXJ
    || instruction.id === cs.ARM_INS_BXNS
    || instruction.id === cs.ARM_INS_BLX
    || instruction.id === cs.ARM_INS_BLXNS;
  if (!registerControlFlow) {
    return operands;
  }

  return [{ kind: "register", name: register }];
}

function normalizeAddress(value: number | bigint): number {
  const address = Number(value);
  if (!Number.isInteger(address) || address < 0 || address > 0xffffffff) {
    throw new DisassemblyBackendError(
      `Capstone returned an invalid ARM address: ${String(value)}`,
    );
  }
  return address;
}

function architecturalPc(address: number, mode: ArmMode): number {
  return mode === "arm"
    ? (address + 8) >>> 0
    : ((address + 4) & ~3) >>> 0;
}

function immediateOperand(
  operands: readonly DecodedArmOperand[],
  index: number,
): number | null {
  const operand = operands[index];
  return operand?.kind === "immediate" ? operand.value >>> 0 : null;
}

function registerOperand(
  operands: readonly DecodedArmOperand[],
  index: number,
): string | null {
  const operand = operands[index];
  return operand?.kind === "register" ? operand.name : null;
}

function structuredPcRelative(
  cs: CapstoneModule,
  instruction: CapstoneInstruction,
  address: number,
  mode: ArmMode,
  operands: readonly DecodedArmOperand[],
): DecodedArmPcRelativeSemantics {
  if (instruction.id === cs.ARM_INS_LDR) {
    const memory = operands.find(
      (operand) => operand.kind === "memory",
    );
    if (
      memory?.kind === "memory"
      && memory.value.baseRegister === "pc"
      && memory.value.indexRegister === null
    ) {
      return {
        kind: "literal-load",
        displacement: memory.value.displacement,
      };
    }
  }

  if (
    instruction.id === cs.ARM_INS_ADD
    && registerOperand(operands, 1) === "pc"
  ) {
    const immediate = immediateOperand(operands, 2);
    if (immediate !== null) {
      return { kind: "address-add", immediate };
    }
  }

  if (
    instruction.id === cs.ARM_INS_SUB
    && registerOperand(operands, 1) === "pc"
  ) {
    const immediate = immediateOperand(operands, 2);
    if (immediate !== null) {
      return { kind: "address-sub", immediate };
    }
  }

  if (instruction.id === cs.ARM_INS_ADR) {
    const target = operands.find(
      (operand) => operand.kind === "immediate",
    );
    if (target?.kind === "immediate") {
      const pc = architecturalPc(address, mode);
      const targetAddress = target.value >>> 0;
      if (targetAddress >= pc) {
        return {
          kind: "address-add",
          immediate: targetAddress - pc,
        };
      }
      return {
        kind: "address-sub",
        immediate: pc - targetAddress,
      };
    }
  }

  return null;
}

function readThumbHalfword(bytes: readonly number[]): number | null {
  const first = bytes[0];
  const second = bytes[1];
  if (first === undefined || second === undefined) {
    return null;
  }
  return first | (second << 8);
}

function readArmWord(bytes: readonly number[]): number | null {
  const first = bytes[0];
  const second = bytes[1];
  const third = bytes[2];
  const fourth = bytes[3];
  if (
    first === undefined
    || second === undefined
    || third === undefined
    || fourth === undefined
  ) {
    return null;
  }
  return (
    first
    | (second << 8)
    | (third << 16)
    | (fourth << 24)
  ) >>> 0;
}

function rotateRight32(value: number, amount: number): number {
  const rotation = amount & 31;
  if (rotation === 0) {
    return value >>> 0;
  }
  return ((value >>> rotation) | (value << (32 - rotation))) >>> 0;
}

function armImmediateOperand(word: number): number {
  const rotate = ((word >>> 8) & 0x0f) * 2;
  return rotateRight32(word & 0xff, rotate);
}

function encodedPcRelative(
  bytes: readonly number[],
  mode: ArmMode,
): DecodedArmPcRelativeSemantics {
  if (mode === "thumb") {
    const halfword = readThumbHalfword(bytes);
    if (halfword === null) {
      return null;
    }

    // Thumb-1 LDR (literal): 01001 Rt:3 Imm8; address = Align(PC, 4) + Imm8*4.
    if ((halfword & 0xf800) === 0x4800) {
      return {
        kind: "literal-load",
        displacement: (halfword & 0xff) << 2,
      };
    }

    // Thumb-1 ADR: 10100 Rd:3 Imm8; address = Align(PC, 4) + Imm8*4.
    if ((halfword & 0xf800) === 0xa000) {
      return {
        kind: "address-add",
        immediate: (halfword & 0xff) << 2,
      };
    }
    return null;
  }

  const word = readArmWord(bytes);
  if (word === null) {
    return null;
  }

  // A32 LDR literal immediate, pre-indexed and without writeback.
  // U is intentionally excluded from the mask because it controls displacement sign.
  if ((word & 0x0f7f0000) === 0x051f0000) {
    const magnitude = word & 0x0fff;
    return {
      kind: "literal-load",
      displacement: (word & 0x00800000) !== 0 ? magnitude : -magnitude,
    };
  }

  // A32 data-processing immediate with Rn=PC, S=0 and non-PC destination.
  if (
    (word & 0x0e100000) === 0x02000000
    && ((word >>> 16) & 0x0f) === 0x0f
    && ((word >>> 12) & 0x0f) !== 0x0f
  ) {
    const opcode = (word >>> 21) & 0x0f;
    const immediate = armImmediateOperand(word);
    if (opcode === 0x04) {
      return { kind: "address-add", immediate };
    }
    if (opcode === 0x02) {
      return { kind: "address-sub", immediate };
    }
  }

  return null;
}

function fallbackOperandsForPcRelative(
  operands: readonly DecodedArmOperand[],
  pcRelative: DecodedArmPcRelativeSemantics,
): readonly DecodedArmOperand[] {
  if (operands.length > 0 || pcRelative?.kind !== "literal-load") {
    return operands;
  }
  return [{
    kind: "memory",
    value: {
      baseRegister: "pc",
      indexRegister: null,
      displacement: pcRelative.displacement,
    },
  }];
}

function normalizeInstruction(
  cs: CapstoneModule,
  decoder: CapstoneHandle,
  instruction: CapstoneInstruction,
  mode: ArmMode,
): DecodedArmInstruction {
  if (instruction.size !== 2 && instruction.size !== 4) {
    throw new DisassemblyBackendError(
      `Unexpected ARM instruction size ${instruction.size}`,
    );
  }

  const address = normalizeAddress(instruction.address);
  const decodedOperands = (instruction.detail.op ?? []).map(
    (operand) => normalizeOperand(cs, decoder, operand),
  );
  const controlFlowOperands = normalizeControlFlowOperands(
    cs,
    instruction,
    decodedOperands,
  );
  const structured = structuredPcRelative(
    cs,
    instruction,
    address,
    mode,
    controlFlowOperands,
  );
  const pcRelative = structured ?? encodedPcRelative(instruction.bytes, mode);
  const operands = fallbackOperandsForPcRelative(controlFlowOperands, pcRelative);
  const cc = instruction.detail.cc;
  return {
    address,
    size: instruction.size,
    bytes: [...instruction.bytes],
    mnemonic: instruction.mnemonic,
    operandsText: instruction.op_str,
    operands,
    isJump:
      hasGroup(instruction, cs.GRP_JUMP)
      || isKnownJumpInstruction(cs, instruction.id),
    isCall:
      hasGroup(instruction, cs.GRP_CALL)
      || isKnownCallInstruction(cs, instruction.id),
    isReturn: hasGroup(instruction, cs.GRP_RET),
    isConditional:
      instruction.id === cs.ARM_INS_CBZ
      || instruction.id === cs.ARM_INS_CBNZ
      || (
        cc !== undefined
        && cc !== cs.ARM_CC_INVALID
        && cc !== cs.ARM_CC_AL
      ),
    switchesMode: instruction.id === cs.ARM_INS_BLX,
    pcRelative,
  };
}

export async function createCapstoneArmBackend(): Promise<ArmDisassemblyBackend> {
  const cs = await loadCapstone();
  let armDecoder: CapstoneHandle | null = null;
  let thumbDecoder: CapstoneHandle | null = null;

  try {
    armDecoder = new cs.Capstone(cs.ARCH_ARM, cs.MODE_ARM);
    thumbDecoder = new cs.Capstone(cs.ARCH_ARM, cs.MODE_THUMB);
    armDecoder.option(cs.OPT_DETAIL, cs.OPT_ON);
    thumbDecoder.option(cs.OPT_DETAIL, cs.OPT_ON);
  } catch (error) {
    try {
      armDecoder?.close();
      thumbDecoder?.close();
    } catch {
      // Preserve the initialization failure as the primary error.
    }
    throw new DisassemblyBackendError(
      `Unable to open Capstone ARM decoders: ${error instanceof Error ? error.message : String(error)}`,
      error,
    );
  }

  if (armDecoder === null || thumbDecoder === null) {
    throw new DisassemblyBackendError("Capstone ARM decoder initialization was incomplete");
  }

  const arm = armDecoder;
  const thumb = thumbDecoder;
  return {
    decodeOne(bytes: Uint8Array, address: number, mode: ArmMode) {
      const decoder = mode === "arm" ? arm : thumb;
      let decoded: DecodedArmInstruction | null = null;
      try {
        decoder.disasm_iter(bytes, address, (instruction) => {
          decoded = normalizeInstruction(cs, decoder, instruction, mode);
          return false;
        });
        return decoded;
      } catch (error) {
        if (error instanceof DisassemblyBackendError) {
          throw error;
        }
        throw new DisassemblyBackendError(
          `Capstone decode failed at 0x${address.toString(16)}: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      }
    },
    close() {
      try {
        arm.close();
        thumb.close();
      } catch (error) {
        throw new DisassemblyBackendError(
          `Unable to close Capstone ARM decoders: ${error instanceof Error ? error.message : String(error)}`,
          error,
        );
      }
    },
  };
}
