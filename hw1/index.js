const xorFn = require('bitwise-xor');

const CIPHERTEXTS = [
    '2d0a0612061b0944000d161f0c1746430c0f0952181b004c1311080b4e07494852',
    '200a054626550d051a48170e041d011a001b470204061309020005164e15484f44',
    '3818101500180b441b06004b11104c064f1e0616411d064c161b1b04071d460101',
    '200e0c4618104e071506450604124443091b09520e125522081f061c4e1d4e5601',
    '304f1d091f104e0a1b48161f101d440d1b4e04130f5407090010491b061a520101',
    '2d0714124f020111180c450900595016061a02520419170d1306081c1d1a4f4601',
    '351a160d061917443b3c354b0c0a01130a1c01170200191541070c0c1b01440101',
    '3d0611081b55200d1f07164b161858431b0602000454020d1254084f0d12554249',
    '340e0c040a550c1100482c4b0110450d1b4e1713185414181511071b071c4f0101',
    '2e0a5515071a1b081048170e04154d1a4f020e0115111b4c151b492107184e5201',
    '370e1d4618104e05060d450f0a104f044f080e1c04540205151c061a1a5349484c'
];

const xor = (str1, st2) =>
    xorFn(Buffer.from(str1, 'hex'), Buffer.from(st2, 'hex')).toString('ascii');

const spaceIndexes = {};

CIPHERTEXTS.forEach(
    ciphertext => (spaceIndexes[ciphertext] = new Array(33).fill(0, 0, 33))
);

const knownKey = (new Array(33)).fill(null, 0, 33);
const knownKeyIndexes = [];

CIPHERTEXTS.forEach(ciphertext => {
    CIPHERTEXTS.forEach(ciphertext2 => {
        if (ciphertext !== ciphertext2) {
            const xorRes = xor(ciphertext, ciphertext2);
            for (let i = 0; i < xorRes.length; i++) {
                const currChar = xorRes[i];
                if (
                    !currChar.match(/[^\x20-\x7E]/g) &&
                    currChar.match(/^[a-z0-9]+$/i)
                ) {
                    spaceIndexes[ciphertext][i] = spaceIndexes[ciphertext][i] + 1;
                }
            }
        }
    });
    const knowSpaceIndexes = [];
    const currentSpaceIndex = spaceIndexes[ciphertext];
    for (let i = 0; i < currentSpaceIndex.length; i++) {
        if (currentSpaceIndex[i] >= 6) {
            knowSpaceIndexes.push(i);
        }
    }
    const spaceXor = xor(ciphertext, '20'.repeat(33));
    knowSpaceIndexes.forEach(index => {
        knownKey[index] = parseInt(spaceXor[index].charCodeAt(0)).toString(16);
        knownKeyIndexes.push(index);
    });
});

const finalKey = knownKey.map(x => x || '00').join('');
console.log(finalKey);
const solution = xor(finalKey, CIPHERTEXTS[0]);
const res = [];
for (let i = 0; i < solution.length; i++) {
    res[i] = knownKeyIndexes.includes(i) ? solution[i] : '?';
}
console.log(res.join(''));

// This prints "?esting ?est?ng can you read t?i>"
// From guessing, the message should be "testing testing can you read this"
// We can crack the key by xoring the hex of this message with the matching
// ciphertext, in this case CIPHERTEXT[0]. Instead of writing code for this,
// I did it manually using http://string-functions.com/string-hex.aspx to 
// find the following key.
const key = "596f75666f756e647468656b657921636f6e67726174756c6174696f6e73212121";
CIPHERTEXTS.forEach(ciphertext => console.log(xor(ciphertext, key)))