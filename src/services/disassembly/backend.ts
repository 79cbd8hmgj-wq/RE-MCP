export type ArmMode = "arm" | "thumb";

export interface DecodedArmMemoryOperand {
  readonly baseRegister: string | null;
  readonly indexRegister: string | null;
  readonly displacement: number;
}

export type DecodedArmOperand =
  | { readonly kind: "immediate"; readonly value: number }
  | { readonly kind: "register"; readonly name: string }
  | { readonly kind: "memory"; readonly value: DecodedArmMemoryOperand }
  | { readonly kind: "other" };

export type DecodedArmPcRelativeSemantics =
  | { readonly kind: "literal-load"; readonly displacement: number }
  | { readonly kind: "address-add"; readonly immediate: number }
  | { readonly kind: "address-sub"; readonly immediate: number }
  | null;

export interface DecodedArmInstruction {
  readonly address: number;
  readonly size: 2 | 4;
  readonly bytes: readonly number[];
  readonly mnemonic: string;
  readonly operandsText: string;
  readonly operands: readonly DecodedArmOperand[];
  readonly isJump: boolean;
  readonly isCall: boolean;
  readonly isReturn: boolean;
  readonly isConditional: boolean;
  readonly switchesMode: boolean;
  readonly pcRelative?: DecodedArmPcRelativeSemantics;
}

export interface ArmDisassemblyBackend {
  decodeOne(
    bytes: Uint8Array,
    address: number,
    mode: ArmMode,
  ): DecodedArmInstruction | null;
  close(): void;
}

export class DisassemblyBackendError extends Error {
  readonly category = "disassembly-backend-failure" as const;

  constructor(message: string, readonly causeValue?: unknown) {
    super(message);
    this.name = "DisassemblyBackendError";
  }
}
