let wasm;
export function __wbg_set_wasm(val) {
    wasm = val;
}


function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_export_2.set(idx, obj);
    return idx;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

const lTextDecoder = typeof TextDecoder === 'undefined' ? (0, module.require)('util').TextDecoder : TextDecoder;

let cachedTextDecoder = new lTextDecoder('utf-8', { ignoreBOM: true, fatal: true });

cachedTextDecoder.decode();

let cachedUint8ArrayMemory0 = null;

function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function getStringFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

function isLikeNone(x) {
    return x === undefined || x === null;
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}
/**
 * @returns {CurvePoint}
 */
export function setup() {
    const ret = wasm.setup();
    return CurvePoint.__wrap(ret);
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}
/**
 * @param {CurvePoint} params
 * @returns {Keypair}
 */
export function keygen(params) {
    _assertClass(params, CurvePoint);
    var ptr0 = params.__destroy_into_raw();
    const ret = wasm.keygen(ptr0);
    return Keypair.__wrap(ret);
}

/**
 * @param {Keypair} keypair
 * @returns {CurvePoint}
 */
export function get_pk(keypair) {
    _assertClass(keypair, Keypair);
    var ptr0 = keypair.__destroy_into_raw();
    const ret = wasm.get_pk(ptr0);
    return CurvePoint.__wrap(ret);
}

/**
 * @param {CurvePoint} params
 * @param {Fr} sk
 * @param {Fr} message
 * @param {bigint | null} [policy]
 * @returns {Signature}
 */
export function sign(params, sk, message, policy) {
    _assertClass(params, CurvePoint);
    var ptr0 = params.__destroy_into_raw();
    _assertClass(sk, Fr);
    var ptr1 = sk.__destroy_into_raw();
    _assertClass(message, Fr);
    var ptr2 = message.__destroy_into_raw();
    const ret = wasm.sign(ptr0, ptr1, ptr2, !isLikeNone(policy), isLikeNone(policy) ? BigInt(0) : policy);
    return Signature.__wrap(ret);
}

let cachedDataViewMemory0 = null;

function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getArrayJsValueFromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    const mem = getDataViewMemory0();
    const result = [];
    for (let i = ptr; i < ptr + 4 * len; i += 4) {
        result.push(wasm.__wbindgen_export_2.get(mem.getUint32(i, true)));
    }
    wasm.__externref_drop_slice(ptr, len);
    return result;
}
/**
 * @param {CurvePoint} params
 * @param {Fr} sk
 * @param {bigint} delegation_spec
 * @returns {DelegationRes}
 */
export function delegate(params, sk, delegation_spec) {
    _assertClass(params, CurvePoint);
    var ptr0 = params.__destroy_into_raw();
    _assertClass(sk, Fr);
    var ptr1 = sk.__destroy_into_raw();
    const ret = wasm.delegate(ptr0, ptr1, delegation_spec);
    return DelegationRes.__wrap(ret);
}

let WASM_VECTOR_LEN = 0;

function passArrayJsValueToWasm0(array, malloc) {
    const ptr = malloc(array.length * 4, 4) >>> 0;
    for (let i = 0; i < array.length; i++) {
        const add = addToExternrefTable0(array[i]);
        getDataViewMemory0().setUint32(ptr + 4 * i, add, true);
    }
    WASM_VECTOR_LEN = array.length;
    return ptr;
}
/**
 * @param {CurvePoint} params
 * @param {SigningToken[]} delegation_info
 * @param {Fr} message
 * @returns {Signature}
 */
export function delegated_sign(params, delegation_info, message) {
    _assertClass(params, CurvePoint);
    var ptr0 = params.__destroy_into_raw();
    const ptr1 = passArrayJsValueToWasm0(delegation_info, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    _assertClass(message, Fr);
    var ptr2 = message.__destroy_into_raw();
    const ret = wasm.delegated_sign(ptr0, ptr1, len1, ptr2);
    return Signature.__wrap(ret);
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}
/**
 * @param {Uint8Array} message
 * @returns {Fr}
 */
export function hash_to_field(message) {
    const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
    const len0 = WASM_VECTOR_LEN;
    const ret = wasm.hash_to_field(ptr0, len0);
    return Fr.__wrap(ret);
}

const CurvePointFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_curvepoint_free(ptr >>> 0, 1));

export class CurvePoint {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(CurvePoint.prototype);
        obj.__wbg_ptr = ptr;
        CurvePointFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        CurvePointFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_curvepoint_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    x() {
        const ret = wasm.curvepoint_x(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @returns {Uint8Array}
     */
    y() {
        const ret = wasm.curvepoint_y(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}

const DelegationResFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_delegationres_free(ptr >>> 0, 1));

export class DelegationRes {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(DelegationRes.prototype);
        obj.__wbg_ptr = ptr;
        DelegationResFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        DelegationResFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_delegationres_free(ptr, 0);
    }
    /**
     * @returns {SigningToken[]}
     */
    delegation_info() {
        const ret = wasm.delegationres_delegation_info(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
    /**
     * @returns {Fr[]}
     */
    revokation_key() {
        const ret = wasm.delegationres_revokation_key(this.__wbg_ptr);
        var v1 = getArrayJsValueFromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 4, 4);
        return v1;
    }
}

const FrFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_fr_free(ptr >>> 0, 1));

export class Fr {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Fr.prototype);
        obj.__wbg_ptr = ptr;
        FrFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        FrFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_fr_free(ptr, 0);
    }
    /**
     * @returns {Uint8Array}
     */
    bytes() {
        const ret = wasm.fr_bytes(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}

const KeypairFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_keypair_free(ptr >>> 0, 1));

export class Keypair {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Keypair.prototype);
        obj.__wbg_ptr = ptr;
        KeypairFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        KeypairFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_keypair_free(ptr, 0);
    }
    /**
     * @returns {Fr}
     */
    sk() {
        const ret = wasm.keypair_sk(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    vk() {
        const ret = wasm.keypair_vk(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
}

const SignatureFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signature_free(ptr >>> 0, 1));

export class Signature {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(Signature.prototype);
        obj.__wbg_ptr = ptr;
        SignatureFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SignatureFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signature_free(ptr, 0);
    }
    /**
     * @returns {Fr}
     */
    sigma_c0() {
        const ret = wasm.signature_sigma_c0(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {Fr}
     */
    sigma_c1() {
        const ret = wasm.signature_sigma_c1(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {Fr}
     */
    sigma_z1() {
        const ret = wasm.signature_sigma_z1(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {Fr}
     */
    theta_m0() {
        const ret = wasm.signature_theta_m0(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {CurvePoint}
     */
    theta_z0() {
        const ret = wasm.signature_theta_z0(this.__wbg_ptr);
        return CurvePoint.__wrap(ret);
    }
}

const SigningTokenFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_signingtoken_free(ptr >>> 0, 1));

export class SigningToken {

    static __wrap(ptr) {
        ptr = ptr >>> 0;
        const obj = Object.create(SigningToken.prototype);
        obj.__wbg_ptr = ptr;
        SigningTokenFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }

    static __unwrap(jsValue) {
        if (!(jsValue instanceof SigningToken)) {
            return 0;
        }
        return jsValue.__destroy_into_raw();
    }

    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        SigningTokenFinalization.unregister(this);
        return ptr;
    }

    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_signingtoken_free(ptr, 0);
    }
    /**
     * @returns {Fr}
     */
    z0() {
        const ret = wasm.signingtoken_z0(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {Fr}
     */
    c0() {
        const ret = wasm.signingtoken_c0(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
    /**
     * @returns {Fr}
     */
    m0() {
        const ret = wasm.signingtoken_m0(this.__wbg_ptr);
        return Fr.__wrap(ret);
    }
}

export function __wbg_buffer_609cc3eee51ed158(arg0) {
    const ret = arg0.buffer;
    return ret;
};

export function __wbg_call_672a4d21634d4a24() { return handleError(function (arg0, arg1) {
    const ret = arg0.call(arg1);
    return ret;
}, arguments) };

export function __wbg_call_7cccdd69e0791ae2() { return handleError(function (arg0, arg1, arg2) {
    const ret = arg0.call(arg1, arg2);
    return ret;
}, arguments) };

export function __wbg_crypto_574e78ad8b13b65f(arg0) {
    const ret = arg0.crypto;
    return ret;
};

export function __wbg_fr_new(arg0) {
    const ret = Fr.__wrap(arg0);
    return ret;
};

export function __wbg_getRandomValues_b8f5dbd5f3995a9e() { return handleError(function (arg0, arg1) {
    arg0.getRandomValues(arg1);
}, arguments) };

export function __wbg_msCrypto_a61aeb35a24c1329(arg0) {
    const ret = arg0.msCrypto;
    return ret;
};

export function __wbg_new_a12002a7f91c75be(arg0) {
    const ret = new Uint8Array(arg0);
    return ret;
};

export function __wbg_newnoargs_105ed471475aaf50(arg0, arg1) {
    const ret = new Function(getStringFromWasm0(arg0, arg1));
    return ret;
};

export function __wbg_newwithbyteoffsetandlength_d97e637ebe145a9a(arg0, arg1, arg2) {
    const ret = new Uint8Array(arg0, arg1 >>> 0, arg2 >>> 0);
    return ret;
};

export function __wbg_newwithlength_a381634e90c276d4(arg0) {
    const ret = new Uint8Array(arg0 >>> 0);
    return ret;
};

export function __wbg_node_905d3e251edff8a2(arg0) {
    const ret = arg0.node;
    return ret;
};

export function __wbg_process_dc0fbacc7c1c06f7(arg0) {
    const ret = arg0.process;
    return ret;
};

export function __wbg_randomFillSync_ac0988aba3254290() { return handleError(function (arg0, arg1) {
    arg0.randomFillSync(arg1);
}, arguments) };

export function __wbg_require_60cc747a6bc5215a() { return handleError(function () {
    const ret = module.require;
    return ret;
}, arguments) };

export function __wbg_set_65595bdd868b3009(arg0, arg1, arg2) {
    arg0.set(arg1, arg2 >>> 0);
};

export function __wbg_signingtoken_new(arg0) {
    const ret = SigningToken.__wrap(arg0);
    return ret;
};

export function __wbg_signingtoken_unwrap(arg0) {
    const ret = SigningToken.__unwrap(arg0);
    return ret;
};

export function __wbg_static_accessor_GLOBAL_88a902d13a557d07() {
    const ret = typeof global === 'undefined' ? null : global;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0() {
    const ret = typeof globalThis === 'undefined' ? null : globalThis;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_SELF_37c5d418e4bf5819() {
    const ret = typeof self === 'undefined' ? null : self;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_static_accessor_WINDOW_5de37043a91a9c40() {
    const ret = typeof window === 'undefined' ? null : window;
    return isLikeNone(ret) ? 0 : addToExternrefTable0(ret);
};

export function __wbg_subarray_aa9065fa9dc5df96(arg0, arg1, arg2) {
    const ret = arg0.subarray(arg1 >>> 0, arg2 >>> 0);
    return ret;
};

export function __wbg_versions_c01dfd4722a88165(arg0) {
    const ret = arg0.versions;
    return ret;
};

export function __wbindgen_init_externref_table() {
    const table = wasm.__wbindgen_export_2;
    const offset = table.grow(4);
    table.set(0, undefined);
    table.set(offset + 0, undefined);
    table.set(offset + 1, null);
    table.set(offset + 2, true);
    table.set(offset + 3, false);
    ;
};

export function __wbindgen_is_function(arg0) {
    const ret = typeof(arg0) === 'function';
    return ret;
};

export function __wbindgen_is_object(arg0) {
    const val = arg0;
    const ret = typeof(val) === 'object' && val !== null;
    return ret;
};

export function __wbindgen_is_string(arg0) {
    const ret = typeof(arg0) === 'string';
    return ret;
};

export function __wbindgen_is_undefined(arg0) {
    const ret = arg0 === undefined;
    return ret;
};

export function __wbindgen_memory() {
    const ret = wasm.memory;
    return ret;
};

export function __wbindgen_string_new(arg0, arg1) {
    const ret = getStringFromWasm0(arg0, arg1);
    return ret;
};

export function __wbindgen_throw(arg0, arg1) {
    throw new Error(getStringFromWasm0(arg0, arg1));
};

