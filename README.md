# capsl-crypto

The encryption code of [capsl](https://capsl.xyz), a service for digital time
capsules. It is published so anyone can check how a capsule is sealed and what it
takes to open one. The rest of capsl is not public.

This repository is a copy. It is generated from capsl's own source by a script,
so what you read here is the code capsl runs, not a tidied version of it. Pull
requests can't be merged here; report problems instead (see the end).

## The model in one paragraph

Every capsule has one random 256-bit key. That key is never stored. It is
rebuilt when the capsule is opened, from one share per **factor**, and every
factor the capsule was sealed with is required. The shares are combined with
HKDF over length-prefixed inputs that also bind each factor's stored ciphertext
and public binding (the construction NIST SP 800-227 §4.6.3 requires for the
result to stay secure). The content is AES-256-GCM. The factor list is covered
by an HMAC, so a factor cannot be quietly removed, and a separate key
commitment ensures a capsule can open to only one content. Only the browser's
built-in WebCrypto and drand's tlock library are used. No cryptography is
invented here.

## The factors

| Factor | What it is | Who can stop an early opening |
|---|---|---|
| `time` | The share is encrypted to a future round of [drand](https://drand.love) quicknet with tlock. Nobody can decrypt it until drand publishes that round. | drand's network, which capsl does not run |
| `release` | A random share capsl's server keeps, wrapped under a master key that is not in the database, and hands out only after the unlock time to whoever the capsule allows | capsl |
| `link` | A secret carried in the part of the capsule's link after `#`, which browsers never send to a server | the person holding the link |

Every capsule with an unlock date needs `time` and `release`, so opening one
early means breaking drand **and** breaching capsl. A capsule opened by password
instead of a date has no `time` factor: capsl releases its share once the
password matches, and the app says plainly that such a capsule has no time lock. A capsule can also require `link`: then capsl
never has every piece, before or after the date, and a lost link means nobody
can open it.

`release` and `link` are symmetric (HKDF, AES-GCM), so a future quantum computer
does not weaken them. `time` uses pairing-based cryptography, which a quantum
computer would break; that is why it is never the only factor.

## Status

capsl is moving off the Internet Computer onto its own server. Today's live app
uses a vetKD time factor; the drand `time` factor and the `release` share in
this repository are their replacement, proven in tests and on a staging server
but not yet live. The envelope itself (`capsuleEnvelope.ts`) is the one the live
app uses now. Some comments still describe the vetKD setup.

## Files

| File | What it does |
|---|---|
| `src/capsuleEnvelope.ts` | Seal and open: factors, combiner, header MAC, key commitment, attachment keys |
| `src/capsuleFormat.ts` | Format version and wrapped-key detection |
| `src/drandTime.ts` | The drand `time` factor, including the choice of round |
| `src/release.ts` | The server side of the `release` share: wrapping, and the rule for who may have it and when. There is no admin override |
| `src/envelope.ts` | The checks the server runs before it accepts a sealed capsule: the right factors in order, the time lock bound to the right drand round, capsl's share bound to this capsule |
| `src/drandRound.ts` | The server's drand round arithmetic (tested against tlock-js) |
| `src/password.ts` | Password verifiers. A password is a gate in front of capsl's share, never key material |
| `src/capsuleClient.ts` | The browser side: which factors a capsule gets, sealing, and opening (copied from capsl's `frontend/src/utils/serverCapsule.ts`; capsl no longer uses the name `capsuleClient.ts`) |
| `src/types.ts` | The stored envelope's shape |
| `test/` | Tests, including cases marked `SHOULD FAIL` that try to open a capsule they must not |

## Run the tests

Needs Node 22 and pnpm.

```bash
pnpm install
pnpm test           # envelope and release share, offline
pnpm test:drand     # the drand factor against the live quicknet network (about 15 seconds)
pnpm typecheck
```

## What has and has not been checked

- No paid outside audit has been done. This repository is how anyone can check
  the code in the meantime.
- tlock's design was reviewed by Kudelski Security (see the
  [tlock README](https://github.com/drand/tlock)). That review covers tlock, not
  this code.

## Reporting a problem

Use GitHub's private vulnerability reporting on this repository (the Security
tab, then "Report a vulnerability"). Please don't open a public issue for a
security problem.
