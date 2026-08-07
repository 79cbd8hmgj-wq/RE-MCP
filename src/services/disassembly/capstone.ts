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

function normalizePcRelative(
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
  const operands = normalizeControlFlowOperands(
    cs,
    instruction,
    decodedOperands,
  );
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
    pcRelative: normalizePcRelative(cs, instruction, address, mode, operands),
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
