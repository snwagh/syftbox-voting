const snarkjs = require("snarkjs");
const crypto = require("crypto");
const BigInt = require("big-integer");
const fs = require("fs").promises;
const util = require('util');
const execPromise = util.promisify(require('child_process').exec);

// Mock logger for snarkjs
const logger = {
    info: (...args) => console.log(...args),
    error: (...args) => console.error(...args),
    debug: (...args) => console.debug(...args),
    warn: (...args) => console.warn(...args)
};

class ElGamalEncryption {
    constructor(p, g) {
        // Using smaller prime for clearer demonstration
        this.p = BigInt(p);
        this.g = BigInt(g);
    }

    generateRandomBigInt(max) {
        const bytes = Math.ceil(max.toString(16).length / 2);
        const randomBytes = crypto.randomBytes(bytes);
        const randomValue = BigInt('0x' + randomBytes.toString('hex'));
        return randomValue % (max - BigInt(1)) + BigInt(1);
    }

    generateKeys() {
        const privateKey = this.generateRandomBigInt(this.p);
        const publicKey = this.g.modPow(privateKey, this.p);
        return { privateKey, publicKey };
    }

    encrypt(message, publicKey) {
        // Use smaller random value for r
        const r = this.generateRandomBigInt(BigInt(1000));
        
        // Calculate c1 = g^r mod p
        const c1 = this.g.modPow(r, this.p);
        
        // Calculate shared secret s = (public_key)^r mod p
        const s = BigInt(publicKey).modPow(r, this.p);
        
        // Encode message as g^m and multiply by shared secret
        const gm = this.g.modPow(BigInt(message), this.p);
        const c2 = (gm * s) % this.p;
        
        console.log(`Debug - Encrypting:
            message: ${message}
            r: ${r}
            c1: ${c1}
            s: ${s}
            gm: ${gm}
            c2: ${c2}`);
        
        return { c1, c2 };
    }

    decrypt(ciphertext, privateKey) {
        const c1 = BigInt(ciphertext.c1);
        const c2 = BigInt(ciphertext.c2);
        
        // Calculate shared secret s = c1^private_key mod p
        const s = c1.modPow(privateKey, this.p);
        
        // Calculate s^(-1) mod p
        const sInverse = s.modInv(this.p);
        
        // Get g^m = c2 * s^(-1) mod p
        const gm = (c2 * sInverse) % this.p;
        
        // Find m by trying small values (since we know m is 0 or 1)
        let message = null;
        let testGm = BigInt(1);
        for (let i = 0; i <= 10; i++) {
            if (testGm === gm) {
                message = i;
                break;
            }
            testGm = (testGm * this.g) % this.p;
        }
        
        console.log(`Debug - Decrypting:
            c1: ${c1}
            c2: ${c2}
            s: ${s}
            sInverse: ${sInverse}
            gm: ${gm}
            message: ${message}`);
        
        return message;
    }

    addCiphertexts(ct1, ct2) {
        // Homomorphic addition is multiplication modulo p
        const c1_result = (BigInt(ct1.c1) * BigInt(ct2.c1)) % this.p;
        const c2_result = (BigInt(ct1.c2) * BigInt(ct2.c2)) % this.p;
        
        console.log(`Debug - Adding ciphertexts:
            ct1.c1: ${ct1.c1}, ct1.c2: ${ct1.c2}
            ct2.c1: ${ct2.c1}, ct2.c2: ${ct2.c2}
            result.c1: ${c1_result}, result.c2: ${c2_result}`);
        
        return { c1: c1_result, c2: c2_result };
    }
}

async function setupZKP() {
    console.log("Setting up ZKP system...");
    
    try {
        // Generate circuit.r1cs
        console.log("Compiling circuit...");
        const { stdout, stderr } = await execPromise("circom circuit.circom --r1cs --wasm");
        if (stderr) {
            console.error("Compilation warning:", stderr);
        }
        console.log("Circuit compilation output:", stdout);

        // Check if Powers of Tau file exists
        if (!await fs.access("pot12_final.ptau").catch(() => false)) {
            console.log("Downloading Powers of Tau file...");
            await execPromise("curl https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau --output pot12_final.ptau");
        }
        
        // Generate zkey with logger
        console.log("Performing trusted setup...");
        
        // Create temporary zkey
        await snarkjs.zKey.newZKey("circuit.r1cs", "pot12_final.ptau", "circuit_0000.zkey", logger);
        
        // Contribute to ceremony
        await snarkjs.zKey.contribute("circuit_0000.zkey", "circuit_final.zkey", "Contributor 1", crypto.randomBytes(32).toString("hex"), logger);
        
        // Export verification key
        const verificationKey = await snarkjs.zKey.exportVerificationKey("circuit_final.zkey", logger);
        await fs.writeFile("verification_key.json", JSON.stringify(verificationKey, null, 2));
        
        return { zkeyPath: "circuit_final.zkey", vkeyPath: "verification_key.json" };
    } catch (error) {
        console.error("Error during ZKP setup:", error);
        throw error;
    }
}

async function castVote(choice, numOptions, zkeyPath, publicKey, elgamal) {
    console.log(`Casting vote for option ${choice}...`);
    
    // Create vote vector
    const voteVector = new Array(numOptions).fill(0);
    voteVector[choice] = 1;
    
    // Generate proof
    const input = { vector: voteVector };
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
        input,
        "circuit_js/circuit.wasm",
        zkeyPath
    );
    
    // Encrypt votes
    const encryptedVotes = voteVector.map(vote => 
        elgamal.encrypt(vote, publicKey)
    );
    
    return { proof, publicSignals, encryptedVotes };
}

async function verifyVote(proof, publicSignals, vkeyPath) {
    const vkey = JSON.parse(await fs.readFile(vkeyPath, "utf8"));
    return snarkjs.groth16.verify(vkey, publicSignals, proof);
}

async function tallyVotes(votes, privateKey, elgamal) {
    const numOptions = votes[0].encryptedVotes.length;
    console.log(`\nDebug - Starting tally for ${votes.length} votes with ${numOptions} options`);
    
    // Initialize tally array with identity element for multiplication
    const tally = new Array(numOptions).fill(null).map(() => ({
        c1: BigInt(1),
        c2: elgamal.g.modPow(BigInt(0), elgamal.p) // Encryption of 0
    }));
    
    // Homomorphically add all votes
    for (let voteIdx = 0; voteIdx < votes.length; voteIdx++) {
        const vote = votes[voteIdx];
        console.log(`\nProcessing vote ${voteIdx + 1}:`);
        
        for (let optionIdx = 0; optionIdx < numOptions; optionIdx++) {
            console.log(`\nOption ${optionIdx}:`);
            const encryptedVote = vote.encryptedVotes[optionIdx];
            tally[optionIdx] = elgamal.addCiphertexts(tally[optionIdx], {
                c1: BigInt(encryptedVote.c1),
                c2: BigInt(encryptedVote.c2)
            });
        }
    }
    
    console.log('\nFinal encrypted tallies before decryption:');
    tally.forEach((t, i) => console.log(`Option ${i}:`, t));
    
    // Decrypt final tallies
    const finalTally = tally.map((enc, i) => {
        console.log(`\nDecrypting tally for option ${i}:`);
        return elgamal.decrypt(enc, privateKey);
    });
    
    return finalTally;
}

async function main() {
    try {
        // Using much smaller prime for testing
        const p = "2039"; // Small prime for testing
        const g = "2";    // Generator
        const numOptions = 3;
        const elgamal = new ElGamalEncryption(p, g);
        
        // Rest of the main function remains the same
        console.log("Setting up voting system...");
        const { zkeyPath, vkeyPath } = await setupZKP();
        const { privateKey, publicKey } = elgamal.generateKeys();
        
        console.log("\nVoting phase...");
        const votes = [];
        const choices = [1, 0, 1];
        
        for (let i = 0; i < choices.length; i++) {
            console.log(`\nProcessing vote for choice ${choices[i]}:`);
            const vote = await castVote(choices[i], numOptions, zkeyPath, publicKey, elgamal);
            
            const isValid = await verifyVote(vote.proof, vote.publicSignals, vkeyPath);
            if (!isValid) {
                throw new Error(`Invalid vote from voter ${i}`);
            }
            console.log(`Vote ${i + 1} verified successfully`);
            
            votes.push(vote);
        }
        
        console.log("\nTallying votes...");
        const finalTally = await tallyVotes(votes, privateKey, elgamal);
        
        console.log("\nFinal tally:", finalTally);
    } catch (error) {
        console.error("Error:", error);
    }
}

main().then(() => process.exit(0));