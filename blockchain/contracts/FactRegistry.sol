// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

interface INoirVerifier {
    function verify(bytes calldata proof, bytes32[] calldata publicInputs) external returns (bool);
}

contract FactRegistry {
    struct VerifiedFact {
        bytes32 verifierIdHash;
        bytes32 subjectTag;
        bytes32 factTypeHash;
        bytes32 issuerPolicyRoot;
        bytes32 schemaHash;
        bytes32 nullifier;
        uint64 verifiedAt;
        uint64 validUntil;
        address submitter;
        bool exists;
    }

    INoirVerifier public noirVerifier;

    mapping(bytes32 => VerifiedFact) public facts;
    mapping(bytes32 => bool) public usedNullifiers;

    event FactVerified(
        bytes32 indexed factKey,
        bytes32 indexed subjectTag,
        bytes32 verifierIdHash,
        bytes32 factTypeHash,
        address submitter
    );

    constructor(address _noirVerifier) {
        noirVerifier = INoirVerifier(_noirVerifier);
    }

    function submitVerifiedFact(
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash,
        bytes32 issuerPolicyRoot,
        bytes32 schemaHash,
        bytes32 nullifier,
        uint64 validUntil
    ) external {
        // 1. Verify the ZK proof
        require(noirVerifier.verify(proof, publicInputs), "Proof verification failed");

        // 2. Check nullifier not used
        require(!usedNullifiers[nullifier], "Nullifier already used");

        // 3. Compute fact key
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));

        // 4. Store the verified fact
        facts[factKey] = VerifiedFact({
            verifierIdHash: verifierIdHash,
            subjectTag: subjectTag,
            factTypeHash: factTypeHash,
            issuerPolicyRoot: issuerPolicyRoot,
            schemaHash: schemaHash,
            nullifier: nullifier,
            verifiedAt: uint64(block.timestamp),
            validUntil: validUntil,
            submitter: msg.sender,
            exists: true
        });

        // 5. Mark nullifier as used
        usedNullifiers[nullifier] = true;

        // 6. Emit event
        emit FactVerified(factKey, subjectTag, verifierIdHash, factTypeHash, msg.sender);
    }

    function getFact(
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash
    ) external view returns (VerifiedFact memory) {
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        return facts[factKey];
    }

    function isFactValid(
        bytes32 verifierIdHash,
        bytes32 subjectTag,
        bytes32 factTypeHash
    ) external view returns (bool) {
        bytes32 factKey = keccak256(abi.encodePacked(verifierIdHash, subjectTag, factTypeHash));
        VerifiedFact storage fact = facts[factKey];
        return fact.exists && (fact.validUntil == 0 || block.timestamp <= fact.validUntil);
    }
}
