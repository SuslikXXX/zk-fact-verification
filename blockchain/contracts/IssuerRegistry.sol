// SPDX-License-Identifier: MIT
pragma solidity >=0.8.21;

contract IssuerRegistry {
    struct IssuerInfo {
        bytes32 pubkeyHash;
        bool active;
        uint64 addedAt;
    }

    address public owner;
    mapping(bytes32 => IssuerInfo) public issuers;

    event IssuerAdded(bytes32 indexed issuerIdHash, bytes32 pubkeyHash);
    event IssuerDeactivated(bytes32 indexed issuerIdHash);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function addIssuer(bytes32 issuerIdHash, bytes32 pubkeyHash) external onlyOwner {
        require(!issuers[issuerIdHash].active, "Issuer already active");
        issuers[issuerIdHash] = IssuerInfo({
            pubkeyHash: pubkeyHash,
            active: true,
            addedAt: uint64(block.timestamp)
        });
        emit IssuerAdded(issuerIdHash, pubkeyHash);
    }

    function deactivateIssuer(bytes32 issuerIdHash) external onlyOwner {
        require(issuers[issuerIdHash].active, "Issuer not active");
        issuers[issuerIdHash].active = false;
        emit IssuerDeactivated(issuerIdHash);
    }

    function isActive(bytes32 issuerIdHash) external view returns (bool) {
        return issuers[issuerIdHash].active;
    }

    function getIssuer(bytes32 issuerIdHash) external view returns (IssuerInfo memory) {
        return issuers[issuerIdHash];
    }
}
