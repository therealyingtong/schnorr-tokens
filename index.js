// const Schnorr = require("./pkg/schnorr_tokens")
import * as Schnorr from "./pkg/schnorr_tokens.js";
console.log("Schnorr:", Schnorr);

const cfg = Schnorr.setup();

const keypair = Schnorr.keygen(cfg);
console.log("private key:", keypair.sk().bytes());


const msg = Schnorr.hash_to_field(new Uint8Array([1, 2, 3, 255, 0]))
console.log("msg:", msg.bytes());
const sig = Schnorr.sign(cfg, keypair.sk(), msg, null)

const delegated_stuff = Schnorr.delegate(cfg, keypair.sk(), 1n);
const sig_delegated = Schnorr.delegated_sign(cfg, delegated_stuff.delegation_info(), msg);