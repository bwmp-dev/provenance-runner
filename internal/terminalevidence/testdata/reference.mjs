// Offline contract reference, not a production SDK, issuer or evidence observer.
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const schema = JSON.parse(
  readFileSync(new URL("schema.json", import.meta.url)),
);
const invalid = () => {
  throw new Error("invalid terminal evidence");
};
export const sha256 = (bytes) =>
  createHash("sha256").update(bytes).digest("hex");

export function canonical(value, depth = 0) {
  if (depth > 12) invalid();
  if (value === null || typeof value === "boolean")
    return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) invalid();
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    if (!value.isWellFormed()) invalid();
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return `[${value.map((v) => canonical(v, depth + 1)).join(",")}]`;
  if (typeof value !== "object") invalid();
  return `{${Object.keys(value)
    .sort()
    .map((k) => `${canonical(k, depth + 1)}:${canonical(value[k], depth + 1)}`)
    .join(",")}}`;
}

// Deliberately small interpreter for this fixed schema; unsupported schema
// keywords fail closed so schema edits cannot silently weaken the reference.
function conforms(value, rule) {
  const known = new Set([
    "$schema",
    "$id",
    "$defs",
    "$ref",
    "type",
    "additionalProperties",
    "required",
    "properties",
    "items",
    "minItems",
    "maxItems",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "const",
    "enum",
    "oneOf",
  ]);
  if (Object.keys(rule).some((k) => !known.has(k))) invalid();
  if (rule.$ref) return conforms(value, schema.$defs[rule.$ref.slice(8)]);
  if (rule.oneOf && rule.oneOf.filter((r) => conforms(value, r)).length !== 1)
    return false;
  if ("const" in rule && value !== rule.const) return false;
  if (rule.enum && !rule.enum.includes(value)) return false;
  if (rule.type === "null" && value !== null) return false;
  if (rule.type === "boolean" && typeof value !== "boolean") return false;
  if (
    rule.type === "integer" &&
    (!Number.isSafeInteger(value) ||
      value < rule.minimum ||
      value > rule.maximum)
  )
    return false;
  if (
    rule.type === "string" &&
    (typeof value !== "string" ||
      !value.isWellFormed() ||
      value.length < (rule.minLength ?? 0) ||
      value.length > (rule.maxLength ?? Infinity) ||
      (rule.pattern && !new RegExp(rule.pattern, "u").test(value)))
  )
    return false;
  if (rule.type === "array") {
    if (
      !Array.isArray(value) ||
      value.length < (rule.minItems ?? 0) ||
      value.length > (rule.maxItems ?? Infinity)
    )
      return false;
    if (!value.every((v) => conforms(v, rule.items))) return false;
  }
  if (rule.type === "object") {
    if (value === null || typeof value !== "object" || Array.isArray(value))
      return false;
    if (rule.required.some((k) => !Object.hasOwn(value, k))) return false;
    if (Object.keys(value).some((k) => !Object.hasOwn(rule.properties, k)))
      return false;
    if (
      !Object.entries(rule.properties).every(([k, r]) => conforms(value[k], r))
    )
      return false;
  }
  return true;
}

function sortedUnique(items) {
  for (let i = 1; i < items.length; i++)
    if (items[i - 1].id >= items[i].id) invalid();
}

function predicate(assertion) {
  const o = assertion.evidence.observation;
  switch (assertion.type) {
    case "startup-ready":
      if (!o.serverLoaded || !o.stabilizationCompleted || !o.serverReady)
        invalid();
      return o.requirementsSatisfied ? "passed" : "failed";
    case "plugin-enabled":
    case "dependency-present":
      if (o.enabled && !o.loaded) invalid();
      return o.loaded && o.enabled ? "passed" : "failed";
    case "clean-shutdown":
      if (!o.shutdownRequested || !o.serverStopped) invalid();
      return o.reportedShutdownRequested ? "passed" : "failed";
    case "console-regex":
      if (!o.registered || !o.executionCompleted) invalid();
      if (!o.evaluated) {
        if (o.passed || !o.outputTruncated) invalid();
        return "skipped";
      }
      if (o.passed && o.outputTruncated) invalid();
      return o.passed ? "passed" : "failed";
    default:
      invalid();
  }
}

// Structural/predicate validity alone DOES NOT validate configured coverage,
// measurement authenticity, event order, or issuance eligibility.
export function validateStructure(raw, digest) {
  try {
    if (
      !(raw instanceof Uint8Array) ||
      raw.byteLength === 0 ||
      raw.byteLength > 32768 ||
      !/^[0-9a-f]{64}$/.test(digest) ||
      sha256(raw) !== digest
    )
      invalid();
    const text = new TextDecoder("utf-8", {
      fatal: true,
      ignoreBOM: true,
    }).decode(raw);
    const value = JSON.parse(text);
    // Canonical equality also rejects duplicate keys and BOM/trailing input.
    if (canonical(value) !== text || !conforms(value, schema)) invalid();
    sortedUnique(value.assertions);
    sortedUnique(value.requested.dependencies);
    if (value.completeness === "complete" && value.runtime === null) invalid();
    for (const a of value.assertions) {
      if (
        canonical(a.evidence.binding) !== canonical(value.binding) ||
        a.id !== a.evidence.id ||
        a.type !== a.evidence.type ||
        a.outcome !== a.evidence.outcome ||
        predicate(a) !== a.outcome ||
        sha256(canonical(a.evidence)) !== a.evidenceSha256
      )
        invalid();
    }
    return value;
  } catch {
    invalid();
  }
}

// expected is immutable job/lease and expected-plan TEST context. Production
// consumers must derive it authoritatively; never accept it from the runner.
export function validateTerminal(raw, digest, expected) {
  try {
    if (
      expected.featureEnabled !== true ||
      !Number.isInteger(expected.wholeMessageBytes) ||
      expected.wholeMessageBytes < raw.length ||
      expected.wholeMessageBytes > 65536
    )
      invalid();
    const value = validateStructure(raw, digest);
    if (
      canonical(value.binding) !== canonical(expected.binding) ||
      canonical(value.requested) !== canonical(expected.requested)
    )
      invalid();
    sortedUnique(expected.assertions);
    const configured = new Map(expected.assertions.map((a) => [a.id, a]));
    for (const a of value.assertions) {
      const plan = configured.get(a.id);
      if (!plan || plan.type !== a.type || plan.supported !== true) invalid();
      const selectors = {
        "startup-ready": [],
        "plugin-enabled": ["targetId"],
        "dependency-present": ["dependencyId", "dependencySha256"],
        "console-regex": ["assertionId", "testId"],
        "clean-shutdown": [],
      };
      if (
        canonical(Object.keys(plan.selector).sort()) !==
        canonical(selectors[a.type])
      )
        invalid();
      for (const [key, v] of Object.entries(plan.selector))
        if (a.evidence.observation[key] !== v) invalid();
      if (
        a.type === "dependency-present" &&
        !value.requested.dependencies.some(
          (d) =>
            d.id === a.evidence.observation.dependencyId &&
            d.sha256 === a.evidence.observation.dependencySha256,
        )
      )
        invalid();
    }
    if (
      value.completeness === "complete" &&
      (expected.assertions.some((a) => a.supported !== true) ||
        configured.size !== value.assertions.length)
    )
      invalid();
    return value;
  } catch {
    invalid();
  }
}

// Generated protobuf wrapper shape; DigestAlgorithm.SHA256 is released value 1.
// expected.wholeMessageBytes must be measured from the containing wire message.
export function validateWrapper(wrapper, expected) {
  try {
    if (
      wrapper.digest.algorithm !== 1 ||
      !(wrapper.digest.value instanceof Uint8Array) ||
      wrapper.digest.value.length !== 32
    )
      invalid();
    return validateTerminal(
      wrapper.canonicalJson,
      Buffer.from(wrapper.digest.value).toString("hex"),
      expected,
    );
  } catch {
    invalid();
  }
}
