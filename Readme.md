### What does this package exist? ###

## What is EigenLayer ##
EigenLayer is a protocol on Ethereum that introduces restaking, allowing stakers to reuse their staked ETH or Liquid Staking Tokens (LST) to secure additional applications and earn rewards. It enables pooled security by letting stakers delegate their ETH to operators who run validation services for Actively Validated Services (AVSs). This approach reduces capital costs and enhances trust for decentralized services by leveraging Ethereum's shared security.

## Centralization issues for AVS Developers ##
In the context of Actively Validated Services (AVS) on the EigenLayer protocol, EigenLayer's sdk does currenctly does not support a consensus mechanism for operators to act as Aggregators for task. Instead AVS developers must build manual intervention or a centralized entities to manage task assignments, which can introduce points of failure and reduce trust in the network.

## How does EigenShift solve this?
The EigenShift wraps around the [raft consensus protocol](https://github.com/hashicorp/raft), enabling operators to act as Aggregators and provides a trustless, programmatic rotation of Aggregators. This package leverages Raft for leader election between operators to elect Aggregators, tailored to handle EigenLayer tasks and operator BLS signatures. This pakcage also provides a mechanism for AVS developers to design how their AVS rotates Aggregators, and ensures consistent, reliable task validation and submission, enhancing the robustness and security of AVS deployments.
