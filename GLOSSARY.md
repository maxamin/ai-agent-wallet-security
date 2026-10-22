# Glossary

- **Blast radius:** the worst outcome a compromised component can cause with the permissions it holds.
- **Canary payload:** a benign, unique injection string used to detect whether an agent follows embedded instructions.
- **Cross-server shadowing:** a tool description from one MCP server influencing how the model uses another server's tools.
- **EIP-7702:** lets an EOA delegate execution to contract code.
- **EntryPoint:** the singleton ERC-4337 contract that validates and executes UserOperations.
- **Indirect prompt injection:** instructions hidden in content the model reads, rather than typed by the user.
- **Kill switch:** a pre-planned action (revoke key, pause module) that stops an agent from transacting.
- **Permit / Permit2:** signature-based token approvals (EIP-2612 and Uniswap's Permit2) that grant allowances without an on-chain approve from the owner.
- **Policy engine:** signer-side rules deciding whether to sign.
- **Quarantined LLM:** a model that reads untrusted content but has no tools and returns only structured data.
- **Session key:** a temporary key with limited, contract-enforced permissions.
- **Smart account:** a contract wallet (ERC-4337) with programmable validation.
- **Taint tracking:** recording which values derive from untrusted input so policies can restrict their use.
- **Tool-definition pinning:** hashing approved tool names, descriptions and schemas and alerting on change.
- **Tool poisoning:** malicious instructions embedded in tool descriptions.
- **UserOperation:** the ERC-4337 pseudo-transaction submitted to bundlers.
