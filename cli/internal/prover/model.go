package prover

// ProverInput as per spec 7.4 - internal, never sent externally
type ProverInput struct {
	BirthDateDays     uint64   `json:"birth_date_days"`
	HolderSecret      string   `json:"holder_secret"`
	IssuerPubkeyX     string   `json:"issuer_pubkey_x"`
	IssuerPubkeyY     string   `json:"issuer_pubkey_y"`
	SigR8X            string   `json:"sig_r8x"`
	SigR8Y            string   `json:"sig_r8y"`
	SigS              string   `json:"sig_s"`
	MerklePath        []string `json:"merkle_path"`
	MerkleIndexBits   []int    `json:"merkle_index_bits"`
	VerifierIDHash    string   `json:"verifier_id_hash"`
	FactTypeHash      string   `json:"fact_type_hash"`
	RequestIDHash     string   `json:"request_id_hash"`
	SchemaHash        string   `json:"schema_hash"`
	IssuerPolicyRoot  string   `json:"issuer_policy_root"`
	CutoffDateDays    uint64   `json:"cutoff_date_days"`
	IdempotencyKeyHash string  `json:"idempotency_key_hash"`
	ValidUntil        uint64   `json:"valid_until"`
}

// ProofPackage as per spec 7.5 - main output of Holder
type ProofPackage struct {
	Version          string   `json:"version"`
	RequestID        string   `json:"request_id"`
	CircuitID        string   `json:"circuit_id"`
	Backend          string   `json:"backend"`
	Proof            string   `json:"proof"`
	PublicInputs     []string `json:"public_inputs"`
	PublicInputLabels []string `json:"public_input_labels"`
	SubjectTag       string   `json:"subject_tag"`
	Nullifier        string   `json:"nullifier"`
	GeneratedAt      string   `json:"generated_at"`
}

// OnchainSubmit as per spec 7.6 - transport package for FactRegistry call
type OnchainSubmit struct {
	Version          string   `json:"version"`
	ContractAddress  string   `json:"contract_address"`
	ChainID          int      `json:"chain_id"`
	Method           string   `json:"method"`
	Proof            string   `json:"proof"`
	PublicInputs     []string `json:"public_inputs"`
	VerifierIDHash   string   `json:"verifier_id_hash"`
	SubjectTag       string   `json:"subject_tag"`
	FactTypeHash     string   `json:"fact_type_hash"`
	IssuerPolicyRoot string   `json:"issuer_policy_root"`
	SchemaHash       string   `json:"schema_hash"`
	Nullifier        string   `json:"nullifier"`
	ValidUntil       uint64   `json:"valid_until"`
}
