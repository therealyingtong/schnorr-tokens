/* tslint:disable */
/* eslint-disable */
export function setup(): CurvePoint;
export function keygen(params: CurvePoint): Keypair;
export function get_pk(keypair: Keypair): CurvePoint;
export function sign(params: CurvePoint, sk: Fr, message: Fr, policy?: bigint | null): Signature;
export function delegate(params: CurvePoint, sk: Fr, delegation_spec: bigint): DelegationRes;
export function delegated_sign(params: CurvePoint, delegation_info: SigningToken[], message: Fr): Signature;
export class CurvePoint {
  private constructor();
  free(): void;
  x(): Uint8Array;
  y(): Uint8Array;
}
export class DelegationRes {
  private constructor();
  free(): void;
  delegation_info(): SigningToken[];
  revokation_key(): Fr[];
}
export class Fr {
  private constructor();
  free(): void;
  bytes(): Uint8Array;
}
export class Keypair {
  private constructor();
  free(): void;
  sk(): Fr;
  vk(): CurvePoint;
}
export class Signature {
  private constructor();
  free(): void;
  sigma_c0(): Fr;
  sigma_c1(): Fr;
  sigma_z1(): Fr;
  theta_m0(): Fr;
  theta_z0(): CurvePoint;
}
export class SigningToken {
  private constructor();
  free(): void;
  z0(): Fr;
  c0(): Fr;
  m0(): Fr;
}
