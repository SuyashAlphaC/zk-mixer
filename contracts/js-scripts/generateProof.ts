import { Barretenberg, Fr, UltraHonkBackend } from "@aztec/bb.js";
import { Noir } from "@noir-lang/noir_js";
import { ethers } from "ethers";
import path from "path";
import fs from "fs";
import { fileURLToPath } from "url";
import { merkleTree } from "./merkleTree";


export default async function generateProof(): Promise<String> {

    try {
        const bb = await Barretenberg.new();
        const circuitPath = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../circuit/target/circuit.json");
        const circuit = JSON.parse(fs.readFileSync(circuitPath, 'utf8'));

        const noir = new Noir(circuit);
        const honk = new UltraHonkBackend(circuit.bytecode, { threads: 1 });
        const inputs = process.argv.slice(2);
        const nullifier = Fr.fromString(inputs[0]);
        const secret = Fr.fromString(inputs[1]);
        const recipient = inputs[2];
        const leaves = inputs.slice(3);

        const nullifierHash = await bb.poseidon2Hash([nullifier]);
        const _commitment = await bb.poseidon2Hash([nullifier, secret]);

        const tree = await merkleTree(leaves);
        const merkleProof = tree.proof(tree.getIndex(_commitment.toString()));

        const inputArray = {
            root: merkleProof.root.toString(),
            nullifier_hash: nullifierHash.toString(),
            recipient: recipient,
            secret: secret.toString(),
            nullifier: nullifier.toString(),
            merkle_proof: merkleProof.pathElements.map(i => i.toString()),
            is_even: merkleProof.pathIndices.map(i => i % 2 == 0)

        };

        const { witness } = await noir.execute(inputArray);
        const { proof, publicInputs } = await honk.generateProof(witness, { keccak: true });

        const result = ethers.AbiCoder.defaultAbiCoder().encode(
            ["bytes", "bytes32[]"],
            [proof, publicInputs]
        );

        return result;
    } catch (error) {
        console.log(error);
        throw error;
    }

}

(
    async () => {
        generateProof()
            .then((result) => {
                process.stdout.write(result);
                process.exit(0);
            })
            .catch((error) => {
                console.error(error);
                process.exit(1);
            });
    }
)();