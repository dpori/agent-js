// import init, { bls_init, bls_verify } from '../vendor/bls/bls';

import CTX from '../../core/javascript';

export let verify: (pk: Uint8Array, sig: Uint8Array, msg: Uint8Array) => boolean;

/**
 *
 * @param pk primary key: Uint8Array
 * @param sig signature: Uint8Array
 * @param msg message: Uint8Array
 * @returns Promise resolving a boolean
 */
export async function blsVerify(
  pk: Uint8Array,
  sig: Uint8Array,
  msg: Uint8Array,
): Promise<boolean> {
  if (!verify) {
    verify = (pk, sig, msg) => {
      const ctx = new CTX.CTX('BLS12381');
      const res = ctx.BLS.core_verify(sig, msg, pk); //ctx.BLS.asciitobytes(msg), pk);

      if (res == 0) {
        // console.log('Signature is OK');
        return true;
      } else {
        // console.log('Signature is *NOT* OK');
        return false;
      }
    };
  }
  return verify(pk, sig, msg);
}
