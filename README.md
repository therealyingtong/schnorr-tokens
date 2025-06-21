# Proxy Signatures for Delegated Spending

*Team FKA Geometry. ZK Hack Berlin 20-22 June, 2025.*

Our project has two contributions:
1. New crypto primitive implementation: anonymous proxy signatures [[AN23]](https://eprint.iacr.org/2023/833). In arkworks and with WASM bindings for in-browser execution.
2. Toy application: Aztec Wallet with anonymous and undetectable delegation. This enables applications like on-chain company cards or on-chain pocket money.


## Anonymous proxy signatures

A classic digital signature looks like this.
![image](https://github.com/therealyingtong/schnorr-tokens/blob/main/readme_diagrams/signature.png?raw=true)

We implement the anonymous proxy signatures of [[AN23]](https://eprint.iacr.org/2023/833), schematically looks like this:
![image](https://github.com/therealyingtong/schnorr-tokens/blob/main/readme_diagrams/delegated_signature.png?raw=true)

The main security properties are:
- signer does not show their private key.
- the verifier cannot know that the signature was delegated.


Additional properties:
- proxy remains anonymous.
- each delegation token is unique.
- delegation tokens can be individually revoked (either by the signer and verifier or verifier only, depending on the verifier's logic).
- fine-grained delegation: the signer can enforce a (private) signing policy (e.g., maximum spend amount)

> For the cryptographer judges, the signature scheme is a sort of two-layered Schnorr signature. In the first layer, the signer signs a token $k$ producing a Schnorr signature $(z, R)$. The $z$ part is then used as a *secret key* in the second Schnorr layer. This time, the proxy can use $z$ to sign a message $m$ of their choice.
> 
> Verification checks that the layers are consistent between each other and with the token $k$. By keeping a list of spent tokens, the verifier can enforce that token are one-time use.

## Applications

We wrote an [Aztec account contract](https://docs.aztec.network/developers/tutorials/codealong/contract_tutorials/write_accounts_contract) that verifies a proxy signature to authorize transactions.

This enables multiple types of applications:
- on-chain **company card**. A company can have a single master wallet and delegate spending capability to its employees. Each employee can be limited in the number of transactions they produce, where they send their payments and the amount they are allowed to spend. The anonymity and privacy of the policy allows to maintain some secrecy as to who can spend what or how budget is allocated.
- on-chain **pocket money**, without creating new wallets. Parents can give virtual pocket money to their children without given the children access to / control of a fully-fledged wallet. The pocket money can also be revoked if the kids are grounded :(

![image](https://github.com/therealyingtong/schnorr-tokens/blob/main/readme_diagrams/spending.jpg?raw=true)

## Navigating the repo

- Interface for proxy signature schemes over a generic curve (arkworks-style) in [`src/lib.rs`](https://github.com/therealyingtong/schnorr-tokens/blob/2807b045a88bdf2e961096d12dcb9ad361229a44/src/lib.rs#L24-L96).
- Our implementation of the concrete [AN23] scheme is in [`src/an23_proxy_signature.rs`](https://github.com/therealyingtong/schnorr-tokens/blob/2807b045a88bdf2e961096d12dcb9ad361229a44/src/an23_proxy_signature.rs#L15-L193)
- WASM bindings for the concrete construction are in [`src/wasm_bindings.rs`](https://github.com/therealyingtong/schnorr-tokens/blob/main/src/wasm_bindings.rs).
- A Noir circuit for signature verification in [`verifier/src/main.nr`](https://github.com/therealyingtong/schnorr-tokens/blob/main/verifier/src/main.nr).

## How to run the examples

You can run the pure-Rust examples as follows:
1. run the `delegate` example. This will create public parameters, a public key and a delegation token.
```shell
cargo run --example delegate    
```
2. run the `proxy_sign` example. This imports the files you created above, signs using the delegation token and verifies the signature.
```shell
cargo run --example proxy_sign    
```

## Compiling to WASM

Instructions to compile to WASM:
- install [`wasm-pack`](https://rustwasm.github.io/wasm-pack/installer/) 
- run `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --target nodejs`