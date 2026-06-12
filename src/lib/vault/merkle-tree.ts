import { sha3_256 } from '@noble/hashes/sha3.js'

/**
 * Merkle Tree Implementation for Vault File Integrity.
 */

const DEFAULT_CHUNK_SIZE = 1024 * 64

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function fromHex(hex: string): Uint8Array {
  const matches = hex.match(/.{1,2}/g)
  if (!matches) return new Uint8Array(0)
  return new Uint8Array(matches.map((byte) => parseInt(byte, 16)))
}

function hashPair(leftHex: string, rightHex: string): string {
  const left = fromHex(leftHex)
  const right = fromHex(rightHex)
  const combined = new Uint8Array(left.length + right.length)
  combined.set(left)
  combined.set(right, left.length)
  return toHex(sha3_256(combined))
}

export interface MerkleTree {
  root: string
  layers: string[][]
  leafCount: number
  chunkSize: number
}

export interface MerkleProofStep {
  position: 'left' | 'right'
  hash: string
}

export interface MerkleProof {
  leafIndex: number
  leafHash: string
  siblings: MerkleProofStep[]
}

export interface MerkleIntegrityMeta {
  algorithm: 'SHA3-256'
  chunkSize: number
  leafCount: number
  root: string
  proof: MerkleProof
}

/**
 * Builds a simple Merkle Tree from file data.
 * For large files, we chunk the data and hash the chunks.
 */
export function buildMerkleTreeFromData(data: Uint8Array, chunkSize = DEFAULT_CHUNK_SIZE): MerkleTree {
  const chunks: Uint8Array[] = []
  
  for (let i = 0; i < data.length; i += chunkSize) {
    chunks.push(data.slice(i, i + chunkSize))
  }
  
  if (chunks.length === 0 && data.length === 0) {
    chunks.push(new Uint8Array(0))
  }
  
  let layer = chunks.map(c => sha3_256(c))
  const tree = [layer.map(h => toHex(h))]
  
  while (layer.length > 1) {
    const nextLayer: Uint8Array[] = []
    for (let i = 0; i < layer.length; i += 2) {
      if (i + 1 < layer.length) {
        const combined = new Uint8Array(layer[i].length + layer[i+1].length)
        combined.set(layer[i])
        combined.set(layer[i+1], layer[i].length)
        nextLayer.push(sha3_256(combined))
      } else {
        nextLayer.push(layer[i]) // Odd leaf
      }
    }
    layer = nextLayer
    tree.push(layer.map(h => toHex(h)))
  }
  
  return {
    root: tree[tree.length - 1][0],
    layers: tree,
    leafCount: chunks.length,
    chunkSize,
  }
}

export function createMerkleProof(tree: MerkleTree, leafIndex = 0): MerkleProof {
  if (!tree.layers.length || !tree.layers[0].length) {
    throw new Error('MERKLE_TREE_EMPTY')
  }
  if (leafIndex < 0 || leafIndex >= tree.layers[0].length) {
    throw new Error('MERKLE_LEAF_INDEX_OUT_OF_RANGE')
  }

  let index = leafIndex
  const siblings: MerkleProofStep[] = []

  for (let level = 0; level < tree.layers.length - 1; level++) {
    const layer = tree.layers[level]
    const isRightNode = index % 2 === 1
    const siblingIndex = isRightNode ? index - 1 : index + 1

    if (siblingIndex < layer.length) {
      siblings.push({
        position: isRightNode ? 'left' : 'right',
        hash: layer[siblingIndex],
      })
    }

    index = Math.floor(index / 2)
  }

  return {
    leafIndex,
    leafHash: tree.layers[0][leafIndex],
    siblings,
  }
}

export function buildMerkleIntegrity(data: Uint8Array, proofLeafIndex = 0): MerkleIntegrityMeta {
  const tree = buildMerkleTreeFromData(data)
  const safeLeafIndex = Math.min(Math.max(0, proofLeafIndex), tree.leafCount - 1)
  return {
    algorithm: 'SHA3-256',
    chunkSize: tree.chunkSize,
    leafCount: tree.leafCount,
    root: tree.root,
    proof: createMerkleProof(tree, safeLeafIndex),
  }
}

export function verifyMerkleProof(root: string, proof: unknown): boolean {
  if (!root || typeof proof !== 'object' || proof === null) return false
  const candidate = proof as Partial<MerkleProof>
  if (typeof candidate.leafHash !== 'string' || !Array.isArray(candidate.siblings)) return false

  let currentHash = candidate.leafHash
  for (const step of candidate.siblings) {
    if (!step || typeof step.hash !== 'string') return false
    if (step.position === 'left') {
      currentHash = hashPair(step.hash, currentHash)
    } else if (step.position === 'right') {
      currentHash = hashPair(currentHash, step.hash)
    } else {
      return false
    }
  }

  return currentHash === root
}

export function verifyMerkleIntegrity(data: Uint8Array, meta: unknown): boolean {
  if (!meta || typeof meta !== 'object') return false
  const candidate = meta as Partial<MerkleIntegrityMeta>
  if (
    candidate.algorithm !== 'SHA3-256' ||
    typeof candidate.root !== 'string' ||
    typeof candidate.chunkSize !== 'number' ||
    typeof candidate.leafCount !== 'number'
  ) {
    return false
  }

  const tree = buildMerkleTreeFromData(data, candidate.chunkSize)
  return (
    tree.root === candidate.root &&
    tree.leafCount === candidate.leafCount &&
    verifyMerkleProof(candidate.root, candidate.proof)
  )
}
