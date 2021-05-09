// SPDX-FileCopyrightText: 2021 Marco Holz <code-iethi9Lu@marcoholz.de>
//
// SPDX-License-Identifier: EUPL-1.2

import CompactEncrypt from './panva-jose/dist/browser/jwe/compact/encrypt.js'
import CompactDecrypt from './panva-jose/dist/browser/jwe/compact/decrypt.js'
import generateKeyPair from './panva-jose/dist/browser/util/generate_key_pair.js'
import parseJwk from './panva-jose/dist/browser/jwk/parse.js'
import { encryptJson, decryptJson, encryptFile, decryptFile } from './simplejose.js'

const fileElement = document.getElementById("input");
const pElement = document.querySelector('#log');
const checkboxElement = document.querySelector('#showJWE');

document.querySelector('#btnEncData').addEventListener('click', encrypt_data, false);
document.querySelector('#btnEncFile').addEventListener('click', encrypt_file, false);

// show file in preview img element
function showFile(file) {
    const preview = document.querySelector('img');
    const reader = new FileReader();
    reader.addEventListener("load", function () {
      // convert image file to base64 string
      preview.src = reader.result;
    }, false);

    reader.readAsDataURL(file);
}

// helper function
function log(text){
  var el = document.createElement('p');
  el.textContent = text;
  pElement.appendChild(el);
}

// encryption data using panva/jose
async function encrypt_data(){
  log('----- encrypt data -----');
  if (!window.isSecureContext) {
    log("This page is not running in secure context. Aborting.");
    log("See https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts for details.");
    return;
  }

  const jsonData = JSON.parse(document.querySelector('#txtPayload').value);
  console.log("jsonData", jsonData);

  // generate key pair
  const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256', { modulusLength: 4096 });
  log("key generation completed");

  console.log(publicKey, privateKey);
  window.localStorage.setItem("publicKey", JSON.stringify(publicKey));
  window.localStorage.setItem("privateKey", JSON.stringify(privateKey));

  const jwkPublicKey = await window.crypto.subtle.exportKey("jwk", publicKey);
  window.localStorage.setItem("jwkPublicKey", JSON.stringify(jwkPublicKey));
  console.log(jwkPublicKey);

  // encrypt
  const a = new Date(); // start measuring
  const jwe = await encryptJson(jsonData, jwkPublicKey);
  const b = new Date(); // stop measuring

  log("panva/jose (compact serialization, encryption) took " + (b-a) + " milliseconds");
  log("jwe size: " + jwe.length/1000 + " KB")

  // log jwe to DOM
  if (checkboxElement.checked) {
    const jweElement = document.querySelector('code');
    jweElement.textContent = jwe;
  }

  // decrypt
  const c = new Date();
  const decryptedJson = await decryptJson(jwe, privateKey);
  const d = new Date();
  log("panva/jose (compact serialization, decryption) took " + (d-c) + " milliseconds");

  if (checkboxElement.checked) {
    const jweElement = document.querySelector('code');
    jweElement.textContent = JSON.stringify(decryptedJson, null, 2);
  }

  console.log("decrypted json", decryptedJson);
}


// encryption file using panva/jose
async function encrypt_file(){
  log('----- encrypt file -----');
  if (!window.isSecureContext) {
    log("This page is not running in secure context. Aborting.");
    log("See https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts for details.");
    return;
  }

  // get file as Uint8Array
  const ui8 = await fileElement.files[0].arrayBuffer();
  log("plaintext size: " + ui8.byteLength/1000 + " KB");

  // generate key pair
  const { publicKey, privateKey } = await generateKeyPair('RSA-OAEP-256', { modulusLength: 4096 });
  log("key generation completed");

  // convert key to JWK
  const jwkPublicKey = await window.crypto.subtle.exportKey("jwk", publicKey);

  // encrypt
  const a = new Date(); // start measuring
  const jwe = await encryptFile(fileElement.files[0], jwkPublicKey);
  const b = new Date();

  log("panva/jose (compact serialization, encryption) took " + (b-a) + " milliseconds");
  log("jwe size: " + jwe.length/1000 + " KB")

  // log jwe to DOM
  if (checkboxElement.checked) {
    const jweElement = document.querySelector('code');
    jweElement.textContent = jwe;
  }

  // decrypt
  const c = new Date();
  const decryptedFile = await decryptFile(jwe, privateKey, fileElement.files[0].name, fileElement.files[0].type);
  const d = new Date();
  log("panva/jose (compact serialization, decryption) took " + (d-c) + " milliseconds");

  //showFile(decryptedFile);
  showFile(decryptedFile);
}
