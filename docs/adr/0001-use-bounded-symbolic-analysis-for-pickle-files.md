# 0001: Use Bounded Symbolic Analysis for Pickle Files

## Status

Accepted

## Context

Python pickle files can execute code as part of deserialization. Loading an untrusted pickle solely to determine whether it is safe would therefore cross the trust boundary the scanner is intended to evaluate.

Static inspection can identify security-relevant behavior without deserializing the artifact. Simple inspection of individual opcodes or global references, however, is easy to evade and does not establish how values and callables are used. At the other extreme, fully reproducing Python's unpickling behavior would require implementing and maintaining increasingly complex pickle and Python runtime semantics.

Static analysis also cannot reliably determine all behavior that may occur during deserialization. The project is expected to eventually complement static inspection with sandboxed dynamic analysis that deserializes artifacts in a tightly controlled environment and observes security-relevant behavior.

The static pickle analyzer therefore needs to provide meaningful security analysis without claiming completeness or growing into a replacement implementation of Python's unpickler.

## Decision

AI Project Scanner will analyze pickle files statically without deserializing untrusted content.

The analyzer will perform bounded symbolic interpretation of pickle operations. It will model enough stack, memo, value, container, global-resolution, and invocation behavior to associate security-relevant callables with their use during deserialization, including supported forms of indirection.

The analyzer will report security-relevant capabilities that it can establish from the pickle instruction stream and will preserve supporting evidence when available. For example, if a pickle invokes `builtins.eval` with a statically available string argument, the finding may include that argument as evidence without claiming to have parsed or evaluated the Python code contained within it.

The initial analysis will focus on capabilities that directly execute code or produce meaningful external effects during deserialization, such as process execution, dynamic code execution, dynamic loading, filesystem access or mutation, and network access. It will not attempt to identify every operation that could contribute to malicious behavior. For example, reading an environment variable is not independently reported merely because its value could later be used by a network operation.

When the analyzer encounters security-relevant pickle semantics that it cannot reliably interpret, it will record an explicit analysis limitation. Unsupported behavior will not be treated as evidence that the artifact is safe.

Findings will describe established behavior and supporting evidence. The initial analyzer will not assign subjective severity, confidence, suspiciousness, or malicious/benign classifications.

Static pickle analysis is one layer of a defense-in-depth strategy. Its coverage may expand where additional static interpretation provides meaningful security value, but complete emulation of pickle deserialization is not a project goal. Future sandboxed dynamic analysis may complement static analysis by safely observing behavior that is difficult or impractical to determine statically.

## Alternatives Considered

### Inspect Security-Relevant Opcodes Independently

The scanner could inspect pickle opcodes and global references individually without tracking their relationships.

This would be simpler to implement, but it would provide weaker evidence and would be relatively easy to evade through ordinary pickle stack operations, memoization, or other indirection. The scanner would also be unable to distinguish between the presence of a callable and its actual use during reconstruction.

### Fully Emulate Pickle Deserialization

The scanner could implement sufficiently complete pickle and Python runtime semantics to determine as much deserialization behavior as possible without executing the artifact.

This could increase static-analysis coverage, but would substantially increase complexity and maintenance burden. It would also risk creating incorrect security conclusions when the scanner's emulation diverges from actual Python behavior.

The project instead favors bounded static analysis combined with explicit limitations and, eventually, isolated dynamic analysis.

### Deserialize During Initial Analysis

The scanner could load the artifact and observe what happens.

This would provide direct runtime behavior but would execute untrusted content as part of routine scanning. Doing so without a deliberately designed isolation boundary would violate the scanner's safe-analysis requirements.

Deserialization may be introduced later only as part of a purpose-built sandboxed analysis capability.

## Consequences

The static pickle analyzer can provide stronger evidence than simple opcode or string matching while remaining substantially smaller and safer than a complete unpickling implementation.

Supported stack manipulation, memoization, and other modeled indirection must not provide trivial ways to evade supported detection rules.

Some valid or malicious pickle behavior will remain unresolved by static analysis. These cases must be surfaced as analysis limitations so users can distinguish between behavior the scanner analyzed and behavior it could not determine.

The scanner must avoid presenting the absence of static findings as proof that an artifact is safe.

The static analyzer can evolve incrementally as additional pickle semantics prove valuable to support. Expansion should be driven by meaningful detection improvements rather than an objective of complete pickle emulation.

Future dynamic analysis can provide an independent layer of evidence by observing deserialization in isolation. Static analysis, dynamic analysis, provenance, integrity verification, and other future controls can therefore contribute complementary evidence rather than requiring any single analyzer to determine artifact trustworthiness on its own.
