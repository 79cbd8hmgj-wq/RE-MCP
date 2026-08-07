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
  return { kind: "other" };
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

function normalizeInstruction(
  cs: CapstoneModule,
  decoder: CapstoneHandle,
  instruction: CapstoneInstruction,
): DecodedArmInstruction {
  if (instruction.size !== 2 && instruction.size !== 4) {
    throw new DisassemblyBackendError(
      `Unexpected ARM instruction size ${instruction.size}`,
    );
  }

  const cc = instruction.detail.cc;
  return {
    address: normalizeAddress(instruction.address),
    size: instruction.size,
    bytes: [...instruction.bytes],
    mnemonic: instruction.mnemonic,
    operandsText: instruction.op_str,
    operands: (instruction.detail.op ?? []).map(
      (operand) => normalizeOperand(cs, decoder, operand),
    ),
    isJump: hasGroup(instruction, cs.GRP_JUMP),
    isCall: hasGroup(instruction, cs.GRP_CALL),
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
          decoded = normalizeInstruction(cs, decoder, instruction);
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
