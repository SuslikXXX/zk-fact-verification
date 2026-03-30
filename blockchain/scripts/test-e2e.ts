import { ethers } from "hardhat";
import * as fs from "fs";

async function main() {
  const deployment = JSON.parse(fs.readFileSync("deployment.json", "utf8"));
  const [signer] = await ethers.getSigners();

  // Read proof and public_inputs from circuit output
  // Use EVM-targeted proof (correct size for Solidity verifier)
  const proofPath = "../circuits/age_over_18_v1/target_evm/proof/proof";
  const publicInputsPath = "../circuits/age_over_18_v1/target_evm/proof/public_inputs";

  const proofBytes = fs.readFileSync(proofPath);
  const publicInputsRaw = fs.readFileSync(publicInputsPath);

  // Parse public inputs (each is 32 bytes)
  const publicInputs: string[] = [];
  for (let i = 0; i < publicInputsRaw.length; i += 32) {
    const chunk = publicInputsRaw.subarray(i, i + 32);
    publicInputs.push("0x" + Buffer.from(chunk).toString("hex"));
  }
  console.log(`Proof size: ${proofBytes.length} bytes`);
  console.log(`Public inputs count: ${publicInputs.length}`);
  console.log("Public inputs:", publicInputs.map((pi, i) => `  [${i}] ${pi}`).join("\n"));

  // 1. Test NoirVerifier.verify directly
  const verifierAddr = deployment.contracts.noirVerifier;
  const verifier = await ethers.getContractAt("HonkVerifier", verifierAddr);

  console.log("\n=== Step 1: Verify proof on-chain ===");
  try {
    const isValid = await verifier.verify(proofBytes, publicInputs);
    console.log("Proof valid:", isValid);
  } catch (e: any) {
    console.log("Verify failed:", e.message?.substring(0, 200));
  }

  // 2. Submit to FactRegistry
  console.log("\n=== Step 2: Submit fact to FactRegistry ===");
  const factRegistryAddr = deployment.contracts.factRegistry;
  const factRegistry = await ethers.getContractAt("FactRegistry", factRegistryAddr);

  // Use some of the public inputs as typed args
  // The circuit public inputs order: verifier_id_hash, fact_type_hash, issuer_policy_root, schema_hash, subject_tag, nullifier, valid_until, cutoff_date_days
  // But Noir adds 16 internal inputs, so user inputs start at index 16
  // For UltraHonk with 24 total: first 16 are internal, then 8 user
  const offset = publicInputs.length - 8; // user inputs are the last 8
  const verifierIdHash = publicInputs[offset + 0];
  const factTypeHash = publicInputs[offset + 1];
  const issuerPolicyRoot = publicInputs[offset + 2];
  const schemaHash = publicInputs[offset + 3];
  const subjectTag = publicInputs[offset + 4];
  const nullifier = publicInputs[offset + 5];
  const validUntilHex = publicInputs[offset + 6];
  const validUntil = BigInt(validUntilHex);

  console.log("verifierIdHash:", verifierIdHash);
  console.log("subjectTag:", subjectTag);
  console.log("factTypeHash:", factTypeHash);
  console.log("nullifier:", nullifier);
  console.log("validUntil:", validUntil.toString());

  try {
    const tx = await factRegistry.submitVerifiedFact(
      proofBytes,
      publicInputs,
      verifierIdHash,
      subjectTag,
      factTypeHash,
      issuerPolicyRoot,
      schemaHash,
      nullifier,
      validUntil,
    );
    const receipt = await tx.wait();
    console.log("TX hash:", receipt?.hash);
    console.log("TX status:", receipt?.status === 1 ? "SUCCESS" : "FAILED");
  } catch (e: any) {
    console.log("Submit failed:", e.message?.substring(0, 300));
  }

  // 3. Lookup fact
  console.log("\n=== Step 3: Lookup fact ===");
  try {
    const fact = await factRegistry.getFact(verifierIdHash, subjectTag, factTypeHash);
    console.log("Fact exists:", fact.exists);
    if (fact.exists) {
      console.log("  verifiedAt:", new Date(Number(fact.verifiedAt) * 1000).toISOString());
      console.log("  validUntil:", new Date(Number(fact.validUntil) * 1000).toISOString());
      console.log("  submitter:", fact.submitter);
    }
  } catch (e: any) {
    console.log("Lookup failed:", e.message?.substring(0, 200));
  }

  // 4. Check isFactValid
  console.log("\n=== Step 4: Check isFactValid ===");
  try {
    const valid = await factRegistry.isFactValid(verifierIdHash, subjectTag, factTypeHash);
    console.log("Fact valid:", valid);
  } catch (e: any) {
    console.log("isFactValid failed:", e.message?.substring(0, 200));
  }

  // 5. Try duplicate nullifier (should fail)
  console.log("\n=== Step 5: Try duplicate nullifier (should revert) ===");
  try {
    await factRegistry.submitVerifiedFact(
      proofBytes,
      publicInputs,
      verifierIdHash,
      subjectTag,
      factTypeHash,
      issuerPolicyRoot,
      schemaHash,
      nullifier,
      validUntil,
    );
    console.log("ERROR: should have reverted!");
  } catch (e: any) {
    console.log("Correctly reverted:", e.message?.includes("Nullifier already used") ? "YES - Nullifier already used" : e.message?.substring(0, 200));
  }

  console.log("\n=== E2E TEST COMPLETE ===");
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
