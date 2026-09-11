/**
 * Offline verification for the Quantum Simulation Range engines.
 *
 * The page at /resources/quantum-simulation exists to be accurate. That claim
 * is only worth anything if something checks it, so this tool holds every
 * engine to its source:
 *
 *   • The inverse QFT is verified against its mathematical definition
 *     (2^(-t/2) Σ_y exp(-2πi·x·y/2^t)) by direct summation, for every basis
 *     state of small registers. If the circuit is wrong, the peaks the page
 *     draws are decoration, not physics.
 *   • Shor's algorithm actually factors: for a matrix of (N, a) pairs, the
 *     factors returned must multiply back to N and both be non-trivial.
 *   • Failure modes are reported honestly — an odd period or a^(r/2) ≡ -1 must
 *     surface as a stated failure, never as a silent retry.
 *   • The CRQC resource model reproduces the published anchor points of the
 *     papers it cites (Gidney & Ekerå 2021, Gidney 2025, Roetteler et al. 2017).
 *   • Live FIPS 203/204/205 output matches the byte lengths tabulated in
 *     src/lib/quantum-sim/nist-standards.ts.
 *   • The TLS 1.3 records are structurally valid: every declared length field
 *     equals the bytes that follow it.
 *
 * No server, no Supabase, no network.
 *
 *   npx tsx tools/quantum-sim-check.ts
 */
import {
  StateVector,
  runShor,
  runShorUntilSuccess,
  continuedFractionConvergents,
  classicalOrder,
  modPow,
  gcd,
  SHOR_TARGETS,
  simulationWall,
} from '../src/lib/quantum-sim/shor'
import { verifyAnchors, estimateRsa, estimateEcc, ANCHOR_HARDWARE } from '../src/lib/quantum-sim/resource-estimator'
import { verifyAgainstStandard, runKemExchange, runSignature, hybridKeyShare } from '../src/lib/quantum-sim/pqc-live'
import { buildClientHello, tls13KeySchedule, transcriptHash } from '../src/lib/quantum-sim/tls-evidence'
import { TLS_NAMED_GROUPS, PQC_SETS, TRANSITION_MILESTONES, milestoneClock } from '../src/lib/quantum-sim/nist-standards'
import { evaluateMosca } from '../src/lib/quantum-sim/mosca'
import { groverFeasibility } from '../src/lib/quantum-sim/grover'
import { SCENARIO_CRYPTO, ATTACK_CHAIN } from '../src/lib/quantum-sim/attack-chain'
import { primitive } from '../src/lib/quantum-sim/classical-crypto'
import { SCENARIOS } from '../src/data/scenario'

let failures = 0
function assert(condition: boolean, label: string) {
  if (condition) {
    console.log(`  ok   ${label}`)
  } else {
    failures += 1
    console.log(`  FAIL ${label}`)
  }
}

/* ══════════════════════════════════════════════════════════ 1. quantum gates */

/**
 * Apply the circuit's inverse QFT to a basis state and compare every amplitude
 * against the closed-form definition. Tolerance is 1e-9, which is far tighter
 * than accumulated float error over these register sizes.
 */
function verifyInverseQft() {
  console.log('\n=== Inverse QFT vs its mathematical definition ===')

  for (const t of [2, 3, 4, 5]) {
    let worst = 0
    const scale = 2 ** t

    for (let x = 0; x < scale; x += 1) {
      // Work register is 0 qubits wide here: we are testing the transform alone.
      const state = new StateVector(t, 0)
      state.re.fill(0)
      state.im.fill(0)
      state.re[x] = 1
      state.inverseQft()

      for (let y = 0; y < scale; y += 1) {
        const angle = (-2 * Math.PI * x * y) / scale
        const expectedRe = Math.cos(angle) / Math.sqrt(scale)
        const expectedIm = Math.sin(angle) / Math.sqrt(scale)
        worst = Math.max(worst, Math.abs(state.re[y] - expectedRe), Math.abs(state.im[y] - expectedIm))
      }
    }
    assert(worst < 1e-9, `t=${t}: max amplitude deviation ${worst.toExponential(2)} < 1e-9`)
  }
}

function verifyGateUnitarity() {
  console.log('\n=== Gate unitarity (norm preservation) ===')
  const state = new StateVector(6, 4)
  state.initialise(1)
  for (let j = 0; j < 6; j += 1) state.hadamard(4 + j)
  for (let j = 0; j < 6; j += 1) state.controlledModularMultiply(4 + j, modPow(7, 2 ** j, 15), 15)
  state.inverseQft()

  let norm = 0
  for (let i = 0; i < state.size; i += 1) norm += state.re[i] ** 2 + state.im[i] ** 2
  assert(Math.abs(norm - 1) < 1e-9, `norm after H → modexp → IQFT is ${norm.toFixed(12)} (expected 1)`)

  const distribution = state.controlDistribution()
  let total = 0
  for (let i = 0; i < distribution.length; i += 1) total += distribution[i]
  assert(Math.abs(total - 1) < 1e-9, `control marginal sums to ${total.toFixed(12)}`)
}

/* ═══════════════════════════════════════════════════════ 2. Shor's algorithm */

function verifyShorFactors() {
  console.log("\n=== Shor's algorithm actually factors ===")

  for (const target of SHOR_TARGETS.filter((t) => t.qubits <= 18)) {
    const attempts = runShorUntilSuccess({ N: target.N, seed: 0xc0ffee }, 12)
    const winner = attempts.find((a) => a.success)
    const ok = Boolean(winner?.factors && winner.factors[0] * winner.factors[1] === target.N && winner.factors[0] > 1 && winner.factors[1] > 1)
    assert(
      ok,
      `N=${target.N} → ${winner?.factors?.join(' × ') ?? 'no factors'} in ${attempts.length} shot(s), ${attempts.reduce((s, a) => s + a.elapsedMs, 0).toFixed(0)} ms`,
    )
  }
}

function verifyShorPeaksMatchOrder() {
  console.log('\n=== Interference peaks land on multiples of 2^t / r ===')

  for (const [N, a] of [
    [15, 7],
    [21, 2],
    [33, 5],
    [35, 3],
  ] as Array<[number, number]>) {
    const result = runShor({ N, a, seed: 0x1234 })
    const order = classicalOrder(a, N)
    if (!order) {
      assert(false, `N=${N}, a=${a}: no classical order`)
      continue
    }
    // The comb has exactly r teeth, at y ≈ k·2^t/r for k = 0..r-1. Each tooth
    // must be present as a peak. When r does not divide 2^t the tooth is spread
    // over the two adjacent bins, so a tooth is "present" if either bin carries
    // significant probability.
    const scale = 2 ** result.controlQubits
    const distribution = result.distribution
    let teethFound = 0
    let combMass = 0
    for (let k = 0; k < order; k += 1) {
      const centre = (k * scale) / order
      const lo = Math.floor(centre)
      const hi = Math.ceil(centre) % scale
      const mass = distribution[lo] + (hi === lo ? 0 : distribution[hi])
      combMass += mass
      if (mass > 0.5 / order) teethFound += 1
    }
    assert(teethFound === order, `N=${N}, a=${a}: all ${order} comb teeth present at k·2^t/r (found ${teethFound})`)
    assert(combMass > 0.7, `N=${N}, a=${a}: ${(combMass * 100).toFixed(1)}% of probability mass sits on the comb`)

    // And nothing tall survives away from the comb.
    const strayMass = result.peaks
      .filter((p) => {
        const k = Math.round(p.phase * order)
        return Math.abs(p.phase - k / order) > 1.5 / scale
      })
      .reduce((s, p) => s + p.probability, 0)
    assert(strayMass < 0.05, `N=${N}, a=${a}: only ${(strayMass * 100).toFixed(2)}% of mass is off the comb`)
  }
}

function verifyShorFailsHonestly() {
  console.log("\n=== Failure modes are reported, not hidden ===")

  // a = 4 mod 15 has order 2 and 4 ≢ -1 (mod 15), so this base can succeed —
  // but only on a shot that does not measure y = 0, which carries 1/r of the
  // probability mass and yields no information at all.
  const fourShots = runShorUntilSuccess({ N: 15, a: 4, seed: 1 }, 8)
  const fourWinner = fourShots.find((s) => s.success)
  assert(fourWinner?.recoveredPeriod === 2, `N=15, a=4 recovers r=2 in ${fourShots.length} shot(s) (got ${fourWinner?.recoveredPeriod})`)
  const zeroShots = fourShots.filter((s) => s.measurement === 0)
  assert(
    zeroShots.every((s) => !s.success && (s.failureReason ?? '').length > 0),
    `every y=0 measurement is reported as an uninformative shot (${zeroShots.length} of ${fourShots.length})`,
  )

  // a = 14 mod 15 has order 2 and 14 ≡ -1 (mod 15): the classic trivial case
  // that can NEVER produce factors, no matter how many shots are taken.
  const trivialShots = runShorUntilSuccess({ N: 15, a: 14, seed: 1 }, 8)
  assert(trivialShots.every((s) => !s.success), 'N=15, a=14 never succeeds — as the mathematics requires')
  assert(
    trivialShots.some((s) => (s.failureReason ?? '').includes('-1')),
    `and states the a^(r/2) ≡ -1 reason rather than fabricating factors (${trivialShots.map((s) => s.failureReason).find((r) => r?.includes('-1'))})`,
  )

  // A base sharing a factor is a classical hit and must say so.
  const lucky = runShor({ N: 35, a: 5, seed: 1 })
  assert(lucky.success && lucky.factors?.includes(5) === true, 'gcd shortcut recognised when gcd(a, N) ≠ 1')
  assert(lucky.stages[0].id === 'lucky', 'gcd shortcut is labelled as a classical shortcut, not a quantum result')

  // Every failure must carry a reason.
  let unreasoned = 0
  for (let a = 2; a < 15; a += 1) {
    if (gcd(a, 15) !== 1) continue
    const r = runShor({ N: 15, a, seed: 7 })
    if (!r.success && !r.failureReason) unreasoned += 1
  }
  assert(unreasoned === 0, 'every unsuccessful shot carries a stated failure reason')
}

function verifyContinuedFractions() {
  console.log('\n=== Continued fractions recover the period ===')
  // 3/8 with limit 15 must yield the convergent 3/8.
  const convergents = continuedFractionConvergents(3, 8, 15)
  assert(convergents.some((c) => c.numerator === 3 && c.denominator === 8), '3/8 appears among its own convergents')

  // A measured y near k·2^t/r resolves to r whenever k is coprime to r.
  const N = 21
  const a = 2
  const order = classicalOrder(a, N)! // r = 6
  const t = 10
  const scale = 2 ** t
  for (const k of [1, 5]) {
    const y = Math.round((k * scale) / order)
    const found = continuedFractionConvergents(y, scale, N).find((c) => c.denominator > 1 && modPow(a, c.denominator, N) === 1)
    assert(found?.denominator === order, `y≈${k}·2^10/${order} resolves to r=${order} (got ${found?.denominator})`)
  }

  // When k shares a factor with r the convergent reduces and the shot recovers
  // a DIVISOR of r, not r. This is a real failure mode, not a bug.
  const reduced = continuedFractionConvergents(Math.round((3 * scale) / order), scale, N).find(
    (c) => c.denominator > 1 && modPow(a, c.denominator, N) === 1,
  )
  assert(reduced === undefined, 'k=3 with r=6 reduces to 1/2 and recovers nothing — the shot is correctly abandoned')
}

function verifySimulationWall() {
  console.log('\n=== The classical-simulation wall is stated honestly ===')
  const small = simulationWall(4)
  const rsa = simulationWall(2048)
  assert(small.bytesLog10 < 10, `4-bit key simulable (10^${small.bytesLog10.toFixed(1)} bytes)`)
  assert(rsa.qubits === 6144, `RSA-2048 needs ${rsa.qubits} logical qubits for the standard circuit`)
  assert(rsa.bytesLog10 > 1000, `RSA-2048 state vector is 10^${Math.round(rsa.bytesLog10)} bytes — beyond any classical machine`)
}

/* ═════════════════════════════════════════════ 3. CRQC resource model anchors */

function verifyResourceAnchors() {
  console.log('\n=== Resource model reproduces its published anchors ===')
  for (const check of verifyAnchors()) {
    assert(check.pass, `${check.label}: published ${check.published.toExponential(2)}, model ${check.computed.toExponential(2)}`)
  }
}

function verifyResourceMonotonicity() {
  console.log('\n=== Resource model behaves monotonically ===')
  const rsa1024 = estimateRsa(1024)
  const rsa2048 = estimateRsa(2048)
  const rsa4096 = estimateRsa(4096)
  assert(rsa1024.physicalQubits < rsa2048.physicalQubits && rsa2048.physicalQubits < rsa4096.physicalQubits, 'physical qubits rise with modulus size')
  assert(rsa1024.runtimeSeconds < rsa2048.runtimeSeconds && rsa2048.runtimeSeconds < rsa4096.runtimeSeconds, 'runtime rises with modulus size')

  const p256 = estimateEcc(256)
  assert(
    p256.logical.qubits < rsa2048.logical.qubits,
    `ECC P-256 (${p256.logical.qubits} logical qubits) is cheaper than RSA-2048 (${rsa2048.logical.qubits}) — the counter-intuitive result that matters`,
  )

  const aboveThreshold = estimateRsa(2048, { ...ANCHOR_HARDWARE, physicalErrorRate: 2e-2 })
  assert(aboveThreshold.infeasible, 'above the surface-code threshold, the model says infeasible rather than printing a number')
  assert((aboveThreshold.infeasibleReason ?? '').includes('threshold'), 'and explains why')

  const better = estimateRsa(2048, { ...ANCHOR_HARDWARE, physicalErrorRate: 1e-4 })
  assert(better.physicalQubits < rsa2048.physicalQubits, 'a better physical error rate needs fewer physical qubits')
}

/* ══════════════════════════════════════════ 4. Live PQC vs the FIPS documents */

function verifyLivePqcMatchesStandards() {
  console.log('\n=== Live FIPS 203/204/205 output matches the published tables ===')
  for (const result of verifyAgainstStandard()) {
    const detail = result.checks.map((c) => `${c.field} ${c.observed}${c.matches ? '' : ` (expected ${c.published})`}`).join(', ')
    assert(result.allMatch, `${result.algorithm}: ${detail}`)
  }

  const exchange = runKemExchange('ML-KEM-768')
  assert(exchange.agreed, 'ML-KEM-768 initiator and responder derive the same 32-byte shared secret')
  assert(exchange.sharedSecretInitiator.length === 32, 'shared secret is 32 bytes')

  const signature = runSignature('ML-DSA-65')
  assert(signature.valid, 'ML-DSA-65 signature verifies')
  assert(signature.tamperDetected, 'ML-DSA-65 rejects a single flipped bit')

  // Every parameter set in the registry must be internally consistent.
  const badRows = PQC_SETS.filter((s) => (s.role === 'kem' ? s.sizes.ciphertext === null : s.sizes.signature === null))
  assert(badRows.length === 0, `every parameter set declares the sizes its role needs (${PQC_SETS.length} sets)`)
  assert(
    PQC_SETS.every((s) => s.category >= 1 && s.category <= 5),
    'every parameter set carries a valid NIST security category',
  )
}

/* ═══════════════════════════════════════════════ 5. TLS records are well-formed */

function readU16(bytes: Uint8Array, at: number): number {
  return (bytes[at] << 8) | bytes[at + 1]
}

function verifyTlsRecords() {
  console.log('\n=== TLS 1.3 records are structurally valid ===')

  for (const group of TLS_NAMED_GROUPS) {
    const keyShare = group.kind === 'hybrid' ? hybridKeyShare(group.name) : undefined
    const evidence = buildClientHello({ serverName: 'payments.example.com', groupId: group.id, keyShare })
    const bytes = evidence.bytes

    assert(bytes[0] === 0x16, `${group.name}: record type is handshake (0x16)`)

    const declaredRecord = readU16(bytes, 3)
    assert(declaredRecord === bytes.length - 5, `${group.name}: record length ${declaredRecord} = ${bytes.length - 5} actual bytes`)

    const declaredHandshake = (bytes[6] << 16) | (bytes[7] << 8) | bytes[8]
    assert(declaredHandshake === bytes.length - 9, `${group.name}: handshake length ${declaredHandshake} = ${bytes.length - 9} actual bytes`)

    // The key_share field must be exactly the length the IANA registry declares.
    const shareField = evidence.fields.find((f) => f.label.includes('public key') || f.label.includes('encapsulation key'))
    assert(shareField !== undefined, `${group.name}: key share field is annotated`)

    const shareBytes = evidence.fields
      .filter((f) => f.label.includes('public key') || f.label.includes('encapsulation key') || f.label.includes('public point'))
      .reduce((sum, f) => sum + f.length, 0)
    assert(shareBytes === group.clientShareBytes, `${group.name}: key share is ${shareBytes} bytes (registry says ${group.clientShareBytes})`)

    assert(evidence.harvestable === group.quantumBroken, `${group.name}: harvestable verdict matches the group's quantum status`)

    // Field annotations must not overlap or exceed the record.
    const sorted = [...evidence.fields].sort((a, b) => a.offset - b.offset)
    let overlaps = 0
    for (let i = 1; i < sorted.length; i += 1) {
      if (sorted[i].offset < sorted[i - 1].offset + sorted[i - 1].length) overlaps += 1
    }
    assert(overlaps === 0, `${group.name}: ${evidence.fields.length} annotated fields, none overlapping`)
  }

  // A hybrid record must carry genuine ML-KEM material, not filler.
  const hybrid = buildClientHello({ serverName: 'x.example', groupId: 0x11ec, keyShare: hybridKeyShare('X25519MLKEM768') })
  const mlkemField = hybrid.fields.find((f) => f.label.startsWith('ML-KEM encapsulation key'))
  assert(mlkemField?.length === 1184, `X25519MLKEM768 carries a real 1184-byte ML-KEM-768 encapsulation key (got ${mlkemField?.length})`)
}


/* ══════════════════════════════════════════════ 5b. the TLS 1.3 key schedule */

function hex(bytes: Uint8Array): string {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('')
}

function verifyKeySchedule() {
  console.log('\n=== TLS 1.3 key schedule (RFC 8446 §7.1) ===')

  const secret = new Uint8Array(32).fill(0x0b)
  const transcript = transcriptHash(buildClientHello({ serverName: 'a.example', groupId: 0x001d }).bytes)
  const schedule = tls13KeySchedule(secret, transcript)

  // RFC 8448 §3: with no PSK and SHA-256, the Early Secret is a fixed constant.
  // If HKDF-Extract is wrong, this fails immediately.
  const early = schedule.steps.find((s) => s.name === 'Early Secret')!
  assert(
    hex(early.value) === '33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a',
    `Early Secret matches the RFC 8448 constant (got ${hex(early.value).slice(0, 16)}…)`,
  )

  assert(schedule.clientWriteKey.length === 32, `client_write_key is 32 bytes (got ${schedule.clientWriteKey.length})`)
  assert(schedule.clientWriteIv.length === 12, `client_write_iv is 12 bytes (got ${schedule.clientWriteIv.length})`)
  assert(
    schedule.steps.filter((s) => s.consumesSharedSecret).length === 1,
    'exactly one step consumes the shared secret — the claim the whole stage rests on',
  )
  assert(
    schedule.steps.find((s) => s.consumesSharedSecret)?.name === 'Handshake Secret',
    'and it is the Handshake Secret extraction',
  )

  // Deterministic: the same inputs must reproduce the same keys, which is what
  // makes a recorded handshake replayable once the shared secret is recovered.
  const repeat = tls13KeySchedule(secret, transcript)
  assert(hex(repeat.clientWriteKey) === hex(schedule.clientWriteKey), 'same shared secret + transcript reproduces the same AEAD key')

  // And genuinely bound to both inputs.
  const otherSecret = tls13KeySchedule(new Uint8Array(32).fill(0x0c), transcript)
  assert(hex(otherSecret.clientWriteKey) !== hex(schedule.clientWriteKey), 'a different shared secret yields a different key')

  const otherTranscript = tls13KeySchedule(secret, transcriptHash(buildClientHello({ serverName: 'b.example', groupId: 0x001d }).bytes))
  assert(hex(otherTranscript.clientWriteKey) !== hex(schedule.clientWriteKey), 'a different transcript yields a different key')

  assert(hex(schedule.clientWriteKey) !== hex(schedule.serverWriteKey), 'client and server directions get different keys')
}

/* ════════════════════════════════════════════════ 6. Models and page bindings */

function verifyMosca() {
  console.log("\n=== Mosca's inequality ===")
  const exposed = evaluateMosca({ shelfLifeYears: 25, migrationYears: 5, crqcYears: 15, baseYear: 2026 })
  assert(exposed.verdict === 'exposed', `X=25 Y=5 Z=15 → exposed (${exposed.headline})`)
  assert(exposed.exposureYears === 15, `exposure is X + Y − Z = 15 years (got ${exposed.exposureYears})`)
  assert(exposed.latestStartYear === 2026 + 15 - 25 - 5, `latest safe start year is ${exposed.latestStartYear}`)
  assert(exposed.alreadyLostYears > 0, 'reports that the safe-start deadline has already passed')

  const safe = evaluateMosca({ shelfLifeYears: 1, migrationYears: 2, crqcYears: 20, baseYear: 2026 })
  assert(safe.verdict === 'safe', `X=1 Y=2 Z=20 → safe (${safe.headline})`)
  assert(safe.alreadyLostYears === 0, 'nothing lost in the safe case')
}

function verifyGroverIsNotABreak() {
  console.log('\n=== Grover is reported as a reduction, not a break ===')
  const aes256 = groverFeasibility(256, 1e9, 1)
  assert(aes256.verdict === 'infeasible', `AES-256 under Grover is infeasible (${aes256.yearsAtRate.toExponential(1)} years)`)
  assert(aes256.explanation.includes('square root'), 'the explanation states that Grover parallelises as the square root')

  assert(aes256.exceedsMaxDepth.generous, "AES-256 exceeds even NIST's most generous MAXDEPTH bound of 2^96")

  const aes128 = groverFeasibility(128, 1e9, 1)
  assert(aes128.operationsBits > 60 && aes128.operationsBits < 68, `AES-128 needs ~2^${aes128.operationsBits.toFixed(0)} sequential operations`)
  assert(
    aes128.exceedsMaxDepth.conservative && !aes128.exceedsMaxDepth.plausible,
    "AES-128 sits between NIST's conservative and plausible MAXDEPTH bounds — the reason it is Category 1, not broken",
  )

  const million = groverFeasibility(256, 1e9, 1e6)
  assert(Math.abs(million.parallelSpeedup - 1000) < 1, `a million machines give a 1000x speed-up, not a million (got ${million.parallelSpeedup.toFixed(0)})`)

  // AES must not be described as broken anywhere in the primitive registry.
  const aes = [primitive('aes-256'), primitive('aes-128')]
  assert(aes.every((p) => p?.verdict !== 'broken'), 'no AES parameter set is labelled "broken"')
  assert(primitive('aes-256')?.verdict === 'safe', 'AES-256 is labelled safe')
  assert(primitive('sha-256')?.attack === 'none', 'SHA-256 carries no quantum attack')
}

function verifyScenarioBindings() {
  console.log('\n=== Every scenario is bound to a real primitive and stage chain ===')
  assert(ATTACK_CHAIN.length === 6, `attack chain has 6 stages (${ATTACK_CHAIN.length})`)
  assert(
    ATTACK_CHAIN.every((s, i) => s.ordinal === i + 1),
    'stage ordinals are 1..6 in order',
  )
  assert(
    ATTACK_CHAIN.filter((s) => s.requiresCrqc).length === 3,
    'exactly three stages require a quantum computer to exist — the first two are happening today',
  )

  const missing = SCENARIOS.filter((s) => !SCENARIO_CRYPTO.some((c) => c.scenarioId === s.id))
  assert(missing.length === 0, `every scenario has a crypto profile (missing: ${missing.map((s) => s.id).join(', ') || 'none'})`)

  const badPrimitive = SCENARIO_CRYPTO.filter((c) => !primitive(c.primitiveId))
  assert(badPrimitive.length === 0, `every crypto profile points at a real primitive (bad: ${badPrimitive.map((c) => c.scenarioId).join(', ') || 'none'})`)

  const badGroup = SCENARIO_CRYPTO.filter((c) => !TLS_NAMED_GROUPS.some((g) => g.id === c.groupId))
  assert(badGroup.length === 0, `every crypto profile points at a real IANA group (bad: ${badGroup.map((c) => c.scenarioId).join(', ') || 'none'})`)

  const unjustified = SCENARIO_CRYPTO.filter((c) => !c.shelfLifeBasis || c.shelfLifeBasis.length < 20)
  assert(unjustified.length === 0, 'every shelf-life figure states its basis')
}

function verifyMilestones() {
  console.log('\n=== Transition milestones are real, dated and ordered ===')
  assert(TRANSITION_MILESTONES.length > 0, `${TRANSITION_MILESTONES.length} milestones registered`)
  const undated = TRANSITION_MILESTONES.filter((m) => Number.isNaN(Date.parse(`${m.date}T00:00:00Z`)))
  assert(undated.length === 0, 'every milestone parses as a date')

  const hardStops = TRANSITION_MILESTONES.filter((m) => m.severity === 'hard-stop')
  assert(hardStops.length >= 2, `${hardStops.length} hard-stop milestones (NIST disallow + NSM-10)`)
  assert(
    TRANSITION_MILESTONES.some((m) => m.id === 'ir8547-disallow' && m.date.startsWith('2036')),
    'NIST IR 8547 "disallowed after 2035" is encoded as 2036-01-01',
  )

  const clock = milestoneClock(TRANSITION_MILESTONES.find((m) => m.id === 'ir8547-disallow')!, Date.parse('2026-01-01T00:00:00Z'))
  assert(clock.days === 3652, `countdown from 2026-01-01 to 2036-01-01 is 3652 days (got ${clock.days})`)
  assert(!clock.elapsed, 'and has not elapsed')
}

/* ═════════════════════════════════════════════════════════════════════ run */

verifyInverseQft()
verifyGateUnitarity()
verifyShorFactors()
verifyShorPeaksMatchOrder()
verifyShorFailsHonestly()
verifyContinuedFractions()
verifySimulationWall()
verifyResourceAnchors()
verifyResourceMonotonicity()
verifyLivePqcMatchesStandards()
verifyTlsRecords()
verifyKeySchedule()
verifyMosca()
verifyGroverIsNotABreak()
verifyScenarioBindings()
verifyMilestones()

console.log(failures === 0 ? '\nAll Quantum Simulation Range checks passed.' : `\n${failures} check(s) FAILED`)
process.exit(failures === 0 ? 0 : 1)
