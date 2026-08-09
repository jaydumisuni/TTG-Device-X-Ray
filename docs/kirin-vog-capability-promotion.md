# Kirin VOG capability promotion

## Purpose

TTG Device X-Ray consumes a promoted, read-only Huawei/Kirin diagnostic capability that was frozen in `jaydumisuni/TECHGUYTOOL-Huawei` at merge `93a8bd705bd9e8d8bade40f0e15181644211812e`.

The upstream Kirin capability-set manifest is `packs/kirin/manifest.json`. The promoted source manifest SHA-256 is `3859e0e71495a4847c8698714494b5ce94264d12d6d8eaa663d4d56c45b8fc9f`.

The local promoted pack is deliberately self-contained. TTG Device X-Ray does not import TECHGUYTOOL Huawei runtime code, Kirin executor code, loaders, repair recipes, firmware writers, or OEMINFO constructors.

## Promoted VOG explanation

For the frozen VOG-L29 C185 replay evidence, TTG Device X-Ray can independently explain the following diagnostic conclusions:

1. a valid and accepted VERSION write did not restore MAIN VERSION;
2. no proven writable standalone `verlist` partition was observed;
3. the missing version state is therefore explained by the replay-supported OEMINFO version-identity rule;
4. Board-Service Fastboot must remain preserved while the unresolved repair still depends on it;
5. restoring stock Fastboot before release conditions is a premature mode-release hazard;
6. stock Fastboot restoration belongs to finalization only;
7. a remaining branding mismatch after core boot recovery is a separate normalization stage, not proof that full board recovery must be repeated.

The evaluator is evidence-conditioned. If the evidence no longer satisfies the recorded causal conditions, it does not force the historical explanation.

## Authority boundary

The promoted capability is `replay_supported` only.

It does not claim physical VOG certification. It cannot authorize:

- loader transfer;
- partition writes;
- OEMINFO construction or writes;
- firmware flashing;
- reboot, unlock or relock operations;
- repair adapters or repair recipes.

The native profile has `write_allowed=false`, no adapter contracts, and `repair_profile_ready=false`.

## Proof

The repository quality gate validates:

- profile registry safety;
- public-repository privacy;
- cross-file Kirin pack provenance;
- package/source maturity and no-execution assertions;
- exact frozen VOG explanation behavior;
- counter-evidence behavior;
- rejection of any promoted execution authority;
- the complete TTG Device X-Ray regression and distribution build.
