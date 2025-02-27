import { Buffer } from 'buffer/';
import { Agent, getDefaultAgent, ReadStateResponse } from './agent';
import * as cbor from './cbor';
import { AgentError } from './errors';
import { hash } from './request_id';
import {
  BinaryBlob,
  blobFromBuffer,
  blobFromText,
  blobFromUint8Array,
  blobToHex,
  blobToUint8Array,
} from '@dfinity/candid';
import { blsVerify } from './utils/bls';

/**
 * A certificate needs to be verified (using {@link Certificate.prototype.verify})
 * before it can be used.
 */
export class UnverifiedCertificateError extends AgentError {
  constructor() {
    super(`Cannot lookup unverified certificate. Call 'verify()' first.`);
  }
}

interface Cert {
  tree: HashTree;
  signature: Buffer;
  delegation?: Delegation;
}

const enum NodeId {
  Empty = 0,
  Fork = 1,
  Labeled = 2,
  Leaf = 3,
  Pruned = 4,
}

export type HashTree =
  | [0]
  | [1, HashTree, HashTree]
  | [2, ArrayBuffer, HashTree]
  | [3, ArrayBuffer]
  | [4, ArrayBuffer];

/**
 * Make a human readable string out of a hash tree.
 * @param tree
 */
export function hashTreeToString(tree: HashTree): string {
  const indent = (s: string) =>
    s
      .split('\n')
      .map(x => '  ' + x)
      .join('\n');
  function labelToString(label: ArrayBuffer): string {
    const decoder = new TextDecoder(undefined, { fatal: true });
    try {
      return JSON.stringify(decoder.decode(label));
    } catch (e) {
      return `data(...${label.byteLength} bytes)`;
    }
  }

  switch (tree[0]) {
    case 0:
      return '()';
    case 1: {
      const left = hashTreeToString(tree[1]);
      const right = hashTreeToString(tree[2]);
      return `sub(\n left:\n${indent(left)}\n---\n right:\n${indent(right)}\n)`;
    }
    case 2: {
      const label = labelToString(tree[1]);
      const sub = hashTreeToString(tree[2]);
      return `label(\n label:\n${indent(label)}\n sub:\n${indent(sub)}\n)`;
    }
    case 3: {
      return `leaf(...${tree[1].byteLength} bytes)`;
    }
    case 4: {
      return `pruned(${blobToHex(blobFromUint8Array(new Uint8Array(tree[1])))}`;
    }
    default: {
      return `unknown(${JSON.stringify(tree[0])})`;
    }
  }
}

interface Delegation extends Record<string, any> {
  subnet_id: Buffer;
  certificate: Buffer;
}

function isBufferEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

export class Certificate {
  private readonly cert: Cert;
  private verified = false;
  private _rootKey: BinaryBlob | null = null;

  constructor(response: ReadStateResponse, private _agent: Agent = getDefaultAgent()) {
    this.cert = cbor.decode(response.certificate);
  }

  public lookupEx(path: Array<ArrayBuffer | string>): ArrayBuffer | undefined {
    this.checkState();
    return lookupPathEx(path, this.cert.tree);
  }
  public lookup(path: Buffer[]): Buffer | undefined {
    this.checkState();
    return lookup_path(path, this.cert.tree);
  }

  public async verify(): Promise<boolean> {
    const rootHash = await reconstruct(this.cert.tree);
    const derKey = await this._checkDelegation(this.cert.delegation);
    const sig = this.cert.signature;
    const key = extractDER(derKey);
    const msg = Buffer.concat([domain_sep('ic-state-root'), rootHash]);
    const res = await blsVerify(key, sig, msg);
    this.verified = res;
    return res;
  }

  protected checkState(): void {
    if (!this.verified) {
      throw new UnverifiedCertificateError();
    }
  }

  private async _checkDelegation(d?: Delegation): Promise<Buffer> {
    if (!d) {
      if (!this._rootKey) {
        if (this._agent.rootKey) {
          this._rootKey = this._agent.rootKey;
          return this._rootKey;
        }

        throw new Error(`Agent does not have a rootKey. Do you need to call 'fetchRootKey'?`);
      }
      return this._rootKey;
    }
    const cert: Certificate = new Certificate(d as any, this._agent);
    if (!(await cert.verify())) {
      throw new Error('fail to verify delegation certificate');
    }

    const lookup = cert.lookupEx(['subnet', d.subnet_id, 'public_key']);
    if (!lookup) {
      throw new Error(`Could not find subnet key for subnet 0x${d.subnet_id.toString('hex')}`);
    }
    return Buffer.from(lookup);
  }
}

const DER_PREFIX = Buffer.from(
  '308182301d060d2b0601040182dc7c0503010201060c2b0601040182dc7c05030201036100',
  'hex',
);
const KEY_LENGTH = 96;

function extractDER(buf: Buffer): Buffer {
  const expectedLength = DER_PREFIX.length + KEY_LENGTH;
  if (buf.length !== expectedLength) {
    throw new TypeError(`BLS DER-encoded public key must be ${expectedLength} bytes long`);
  }
  const prefix = buf.slice(0, DER_PREFIX.length);
  if (!isBufferEqual(prefix, DER_PREFIX)) {
    throw new TypeError(
      `BLS DER-encoded public key is invalid. Expect the following prefix: ${DER_PREFIX}, but get ${prefix}`,
    );
  }

  return buf.slice(DER_PREFIX.length);
}

/**
 * @param t
 */
export async function reconstruct(t: HashTree): Promise<Buffer> {
  switch (t[0]) {
    case NodeId.Empty:
      return hash(domain_sep('ic-hashtree-empty') as BinaryBlob);
    case NodeId.Pruned:
      return Buffer.from(t[1] as ArrayBuffer);
    case NodeId.Leaf:
      return hash(
        Buffer.concat([
          domain_sep('ic-hashtree-leaf'),
          Buffer.from(t[1] as ArrayBuffer),
        ]) as BinaryBlob,
      );
    case NodeId.Labeled:
      return hash(
        Buffer.concat([
          domain_sep('ic-hashtree-labeled'),
          Buffer.from(t[1] as ArrayBuffer),
          Buffer.from(await reconstruct(t[2] as HashTree)),
        ]) as BinaryBlob,
      );
    case NodeId.Fork:
      return hash(
        Buffer.concat([
          domain_sep('ic-hashtree-fork'),
          Buffer.from(await reconstruct(t[1] as HashTree)),
          Buffer.from(await reconstruct(t[2] as HashTree)),
        ]) as BinaryBlob,
      );
    default:
      throw new Error('unreachable');
  }
}

function domain_sep(s: string): Buffer {
  const buf = Buffer.alloc(1);
  buf.writeUInt8(s.length, 0);
  return Buffer.concat([buf, Buffer.from(s)]);
}

/**
 *
 * @param path
 * @param tree
 */
export function lookupPathEx(
  path: Array<ArrayBuffer | string>,
  tree: HashTree,
): ArrayBuffer | undefined {
  const maybeReturn = lookup_path(
    path.map(p => {
      if (typeof p === 'string') {
        return blobFromText(p);
      } else {
        return blobFromUint8Array(new Uint8Array(p));
      }
    }),
    tree,
  );
  return maybeReturn && blobToUint8Array(blobFromBuffer(maybeReturn));
}

/**
 * @param path
 * @param tree
 */
export function lookup_path(path: Buffer[], tree: HashTree): Buffer | undefined {
  if (path.length === 0) {
    switch (tree[0]) {
      case NodeId.Leaf: {
        return Buffer.from(tree[1] as ArrayBuffer);
      }
      default: {
        return undefined;
      }
    }
  }
  const t = find_label(path[0], flatten_forks(tree));
  if (t) {
    return lookup_path(path.slice(1), t);
  }
}
function flatten_forks(t: HashTree): HashTree[] {
  switch (t[0]) {
    case NodeId.Empty:
      return [];
    case NodeId.Fork:
      return flatten_forks(t[1] as HashTree).concat(flatten_forks(t[2] as HashTree));
    default:
      return [t];
  }
}
function find_label(l: Buffer, trees: HashTree[]): HashTree | undefined {
  if (trees.length === 0) {
    return undefined;
  }
  for (const t of trees) {
    if (t[0] === NodeId.Labeled) {
      const p = Buffer.from(t[1] as ArrayBuffer);
      if (isBufferEqual(l, p)) {
        return t[2];
      }
    }
  }
}
