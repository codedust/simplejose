// SPDX-FileCopyrightText: 2021 2021 Marco Holz <code-iethi9Lu@marcoholz.de>
//
// SPDX-License-Identifier: EUPL-1.2

import CompactEncrypt from './panva-jose/dist/browser/jwe/compact/encrypt.js'
import CompactDecrypt from './panva-jose/dist/browser/jwe/compact/decrypt.js'
import parseJwk from './panva-jose/dist/browser/jwk/parse.js'
import validateJwk from './validate-jwk.js'

const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MiB

class InvalidJWKException extends Error {}
class InvalidFileException extends Error {}

async function importJwkPublicKey(jwkPublicKey) {
  // validate jwk agains JSON schema
  if (!validateJwk(jwkPublicKey)) {
    throw new InvalidJWKException('JWK did not match JSON schema specification');
  }

  // TODO: verify x5c chain
  console.warn("TODO: verify x5c chain");

  // parse JWK
  const publicKey = await parseJwk(jwkPublicKey, 'RSA-OAEP-256');

  // verify that modulus length is at least 4096
  if (publicKey.algorithm.modulusLength < 4096) {
    throw new InvalidJWKException('JWK has invalid modulus length');
  }

  // TODO: if key has been imported successfully (including successful x5c validation), store imported key inside module for performance, see https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/digest#converting_a_digest_to_a_hex_string)

  return publicKey;
}

// encrypt json data
export async function encryptJson(jsonData, jwkPublicKey){
  // import JWK public key
  const publicKey = await importJwkPublicKey(jwkPublicKey);

  // encode json data as string
  const str = JSON.stringify(jsonData);

  // encode string as Uint8Array
  const encoder = new TextEncoder();
  const ui8 = encoder.encode(str);

  // encrypt Uint8Array to jwe compact serialization
  const jwe = await new CompactEncrypt(ui8)
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(publicKey);

  return jwe;
}

// decrypt json data using panva/jose
export async function decryptJson(jwe, privateKey){
  // decrypt jwe to Uint8Array
  const { plaintext, protectedHeader } = await CompactDecrypt(jwe, privateKey)

  // decode Uint8Array to string
  const decoder = new TextDecoder();
  const str = decoder.decode(plaintext);

  // parse string as JSON
  const jsonData = JSON.parse(str);

  return jsonData;
}

// encryption File object
export async function encryptFile(file, jwkPublicKey){
  if (!file instanceof File) {
    throw new InvalidFileException('file argument is not of type File');
  }

  if (file.size > MAX_FILE_SIZE) {
    throw new InvalidFileException('File is too large')
  }

  // convert file to Uint8Array
  const ui8 = await file.arrayBuffer();

  // import JWK public key
  const publicKey = await importJwkPublicKey(jwkPublicKey);

  // encrypt file to JWE compact serialization
  const jwe = await new CompactEncrypt(ui8)
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(publicKey);

  return jwe;
}

// decrypt file to File object
export async function decryptFile(jwe, privateKey, fileName, fileType){
  // decrypt jwe to Uint8Array
  const { plaintext, protectedHeader } = await CompactDecrypt(jwe, privateKey)

  // convert Uint8Array to File
  const file = new File([plaintext], fileName, {
    type: fileType
  });
  return file;
}
