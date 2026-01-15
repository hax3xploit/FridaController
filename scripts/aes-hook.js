/*
    author: Abdullah K - https://github.com/hax3xploit
*/

'use strict';

console.log("🔥 AES Hook Script Loaded 🔥");

function bytesToString(arr) {
    return String.fromCharCode.apply(null, new Uint8Array(arr));
}

function bytesToHex(arr) {
    return Array.prototype.map.call(new Uint8Array(arr), x => ('00' + x.toString(16)).slice(-2)).join('');
}

function bytesToBase64(arr) {
    return Java.use('android.util.Base64').encodeToString(arr, 2); // Base64.NO_WRAP = 2
}

Java.perform(function () {
    const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (bytes, algo) {
        const result = this.$init(bytes, algo);
        console.log(`\n🔑 [SecretKeySpec]`);
        console.log(`  • Key (String):  ${bytesToString(bytes)}`);
        console.log(`  • Key (Hex):     ${bytesToHex(bytes)}`);
        console.log(`  • Key (Base64):  ${bytesToBase64(bytes)}`);
        //console.log(`  • Stack Trace (SecretKeySpec):\n${Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())}`);
        return result;
    };

    const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function (bytes) {
        const result = this.$init(bytes);
        console.log(`\n🧊 [IvParameterSpec]`);
        console.log(`  • IV (String):   ${bytesToString(bytes)}`);
        console.log(`  • IV (Hex):      ${bytesToHex(bytes)}`);
        console.log(`  • IV (Base64):   ${bytesToBase64(bytes)}`);
        //console.log(`  • Stack Trace (IvParameterSpec):\n${Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())}`);
        return result;
    };

    const Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (transformation) {
        const result = this.getInstance(transformation);
        console.log(`\n🔐 [Cipher Instance]`);
        console.log(`  • Transformation: ${transformation}`);
        return result;
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (opmode, key, iv) {
        const result = this.init(opmode, key, iv);
        const modeStr = (opmode === 1) ? 'ENCRYPT' : (opmode === 2) ? 'DECRYPT' : `UNKNOWN (${opmode})`;
        console.log(`\n⚙️  [Cipher.init()]`);
        console.log(`  • Mode:          ${modeStr}`);
        return result;
    };

    Cipher.doFinal.overload('[B').implementation = function (input) {
        console.log(`\n🚀 [doFinal()]`);
        console.log(`  • Input (String):   ${bytesToString(input)}`);
        console.log(`  • Input (Hex):      ${bytesToHex(input)}`);
        console.log(`  • Input (Base64):   ${bytesToBase64(input)}`);

        const result = this.doFinal(input);

        console.log(`  • Output (Hex):     ${bytesToHex(result)}`);
        console.log(`  • Output (Base64):  ${bytesToBase64(result)}`);

        return result;
    };
});
