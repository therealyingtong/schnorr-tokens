# ZK Hack Berlin

Our project has two contributions:
1. New crypto primitive implementation: anonymous proxy signatures [[AN23]](https://eprint.iacr.org/2023/833). In arkworks and with WASM compilation target.
2. Toy application: Aztec Wallet with anonymous and undetectable delegation. This is the on-chain equivalent of a blank cheque.


## Anonymous proxy signatures

A classic digital signature looks like this.
![image](https://hackmd.io/_uploads/ryh-NSNVlx.png)

We implement the anonymous proxy signatures of [[AN23]](https://eprint.iacr.org/2023/833), schematically looks like this:
![image](https://hackmd.io/_uploads/H1TG4B44xe.png)

The main security properties are:
- signer does not show their private key.
- the verifier cannot know that the signature was delegated.


Additional properties:
- proxy remains anonymous
- fine-grained delegation:
    - choose the number of allowed signatures.
    - enforce a (private) signing policy (e.g., maximum spend amount)

> For the cryptographer judges, the signature scheme is a sort of two-layered Schnorr signature. In the first layer, the signer signs a token $k$ producing a Schnorr signature $(z, R)$. The $z$ part is then used as a *secret key* in the second Schnorr layer. This time, the proxy can use $z$ to sign a message $m$ of their choice.
> 
> Verification checks that the layers are consistent between each other and with the token $k$. By keeping a list of spent tokens, the verifier can enforce that token are one-time use.

## Application