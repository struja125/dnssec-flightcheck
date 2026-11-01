"""Built-in lab: executes a plan with real DNSSEC signatures and emulated validating resolvers.

Everything runs in one process on a virtual clock, so a plan that spans days is executed in
seconds. DNS messages are encoded to and decoded from wire format and all signatures are real
(generated and verified with dnspython / cryptography).
"""
