import assert from 'node:assert/strict';
import test from 'node:test';

import { accountKeyFromPublicKey, fromHex, toHex } from '../src/codec.ts';

test('ed25519 transaction public keys map to legacy account bytes', async () => {
    const publicKey = fromHex(`00${'11'.repeat(32)}00`);

    assert.equal(toHex(await accountKeyFromPublicKey(publicKey)), '11'.repeat(32));
});

test('secp256r1 transaction public keys map to hashed account bytes', async () => {
    const publicKey = fromHex(`01${'22'.repeat(33)}`);
    const expected = new Uint8Array(
        await crypto.subtle.digest('SHA-256', publicKey.buffer.slice(0)),
    );

    assert.equal(toHex(await accountKeyFromPublicKey(publicKey)), toHex(expected));
});
