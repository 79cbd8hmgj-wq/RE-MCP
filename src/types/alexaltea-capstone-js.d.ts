declare module "@alexaltea/capstone-js" {
  export interface CapstoneOperand {
    readonly type: number;
    readonly imm?: number;
    readonly reg?: number;
  }

  export interface CapstoneInstruction {
    readonly id: number;
    readonly address: number | bigint;
    readonly size: number;
    readonly bytes: readonly number[];
    readonly mnemonic: string;
    readonly op_str: string;
    readonly detail: {
      readonly groups?: readonly number[];
      readonly cc?: number;
      readonly op?: readonly CapstoneOperand[];
    };
  }

  export interface CapstoneHandle {
    option(option: number, value: number): void;
    disasm_iter(
      bytes: ArrayLike<number>,
      address: number,
      callback: (instruction: CapstoneInstruction, pointer: number) => boolean,
    ): number;
    reg_name(registerId: number): string;
    close(): void;
  }

  export interface CapstoneModule {
    readonly ARCH_ARM: number;
    readonly MODE_ARM: number;
    readonly MODE_THUMB: number;
    readonly OPT_DETAIL: number;
    readonly OPT_ON: number;
    readonly GRP_JUMP: number;
    readonly GRP_CALL: number;
    readonly GRP_RET: number;
    readonly ARM_OP_IMM: number;
    readonly ARM_OP_REG: number;
    readonly ARM_CC_INVALID: number;
    readonly ARM_CC_AL: number;
    readonly ARM_INS_B: number;
    readonly ARM_INS_BL: number;
    readonly ARM_INS_BLX: number;
    readonly ARM_INS_BLXNS: number;
    readonly ARM_INS_BX: number;
    readonly ARM_INS_BXJ: number;
    readonly ARM_INS_BXNS: number;
    readonly ARM_INS_CBZ: number;
    readonly ARM_INS_CBNZ: number;
    readonly Capstone: new (architecture: number, mode: number) => CapstoneHandle;
  }

  export type CapstoneFactory = () => Promise<CapstoneModule>;

  const MCapstone: CapstoneFactory;
  export default MCapstone;
}
