# What does this package exist? ##

## What is EigenLayer ###
EigenLayer is a protocol on Ethereum that introduces restaking, allowing stakers to reuse their staked ETH or Liquid Staking Tokens (LST) to secure additional applications and earn rewards. It enables pooled security by letting stakers delegate their ETH to operators who run validation services for Actively Validated Services (AVSs). This approach reduces capital costs and enhances trust for decentralized services by leveraging Ethereum's shared security.

## Centralization issues for AVS Developers ###
In the context of Actively Validated Services (AVS) on the EigenLayer protocol, EigenLayer's sdk does currenctly does not support a consensus mechanism for operators to act as Aggregators for task. Instead AVS developers must build manual intervention or a centralized entities to manage task assignments, which can introduce points of failure and reduce trust in the network.

## How does EigenShift solve this? ###
The EigenShift wraps around the [raft consensus protocol](https://github.com/hashicorp/raft), enabling operators to act as task generators and aggregators by providing a trustless, programmatic framework that allows develoeprs to define how task are created, processed and submitted on-chain. This package leverages Raft for leader election between operators to elect aggregators, tailored to handle EigenLayer tasks and operator BLS signatures. This pakcage also provides a mechanism for AVS developers to design how their AVS rotates Aggregators, and ensures consistent, reliable task validation and submission, enhancing the robustness and security of AVS deployments.

Thanks to using Go generics this package only has 3 external dependencies and provides developers with a framework to define their custom operator consesus:

- EigenLayer's go sdk: https://github.com/Layr-Labs/eigensdk-go
- Go ethereum: https://github.com/ethereum/go-ethereum
- Raft Protocol Implementation: https://github.com/hashicorp/raft

## Integrating with EigenShift

We provide the method `NewAVSConcensusEngine(...)` which initializes the `TaskConsensusManager` on the given operator and returns a `TaskConsensusManager` object. This interface provides AVS developers the consensus methods they need to control consensus:

```golang
// Type T is the task request type is sent from the leader to followers
// Type K is the task response type from followers to the leader
// Type S is the bls signed response type submitted to the leader

type TaskConsensusManager[T any, K any, S any] interface {
	// must be called for an operator to initialize raft rpc server and decide if a new cluster should be bootstraped
	InitializeRaftRpcServer(shouldBootstrapCluster bool, operatorId string) error
	// attempts to join an existing raft cluster
	JoinExistingOperatorCluster(joinHttpUrl string, latestBlock uint64) error
	// Returns true if the operator is the leader on a cluster. False otherwise
	IsLeader() (bool, string)
	// Triggers a new leader election within the raft cluster. Only the current leader can trigger this
	TriggerElection()
	// Method to trigger the current leader of a cluster to send a task request to follower
	// Only the leader can call this method
	LeaderSendTaskRequestToFollowers(taskRequest T) error

	GetHttpBindingUrl() string
}
```

### What do AVS developers need to provide?
In order to call `NewAVSConcensusEngine(...)` and generate a `TaskConsensusManager` AVS developers must provide 3 things:

1 - Define the 3 generic types for their AVS `T`, `K`, and `S`:

- Type `T` is the task request type. This is the format of the task struct sent from the leader to followers

- Type `K` is the task response type. This is the format of the task response sent from followers back to the leader

- Type `S` is the bls signed response of an operator. This is the format of the signed response sent from followers to the leader. We provide a default signed response type that developers can use called `SignedTaskResponse`

2 - Define the required config for the raft server `OperatorRaftConfig` which includes:

- `RpcUrl`: Url that the operator will expose to use for the raft protocol. This is the communication channel leaders send messages to followers + elections

- `HttpUrl`: Url that the operator will expose to use for custom task response server. This is the communication channel operators join existing clusters + submit final task responses

- `FileStorageDirectory`: Directory where the raft protocol distributed replicated log will be stored

3 - Define the callbacks that will be executed over the lifecycle of the task. We provide a struct `TaskConsensusCallbacks` that defines all the callbacks AVS developers need to implements. The 5 callbacks are:

```go
// Type T is the task request type is sent from the leader to followers
// Type K is the task response type from followers to the leader
// Type S is the bls signed response type submitted to the leader

// Method that is triggered when a follower receives a task request (T) from the current leader. The follower resonse (K) is returned
type onTaskRequest[T any, K any] func(taskRequest T) (taskResponses []K, err error)

// Method that is triggered when a follower wants to sign their task response (K) with a BLS signature and submit that response to the leader
type onSubmitTaskToLeader[T any, K any, S any] func(taskRequest T, taskResponse []K) (signedResponse S, leaderUrl string, err error)

// Method that is triggered when the current leader receives a task response (K) from a follower and generates a taskDigest
// The task digest is essentially an unsigned hash of the task fileds and values
type onLeaderProcessTaskResponse[K any] func(taskResponse K, w http.ResponseWriter) (taskIndex uint32, taskResponseDigest [32]byte)

// Method that is used to verify that a given operator address
type isRegisteredOperator func(operatorAddress common.Address) (bool, error)

// Method that fetches the raftRpc and http urls for a given operator address
// It is up to the AVS developers to implement how operator urls are discovered by other operators
type fetchOperatorUrl func(operatorAddress common.Address) (OperatorRaftConfig, error)
```

### Initialization of consensus server

Once the `TaskConsensusManager` is initialized AVS developers need to call these 2 methods in order for the operator to either start or join an existing consensus cluster. It is up to the AVS developer to define when and how these methods are called:

1 - `TaskConsensusManager.InitializeRaftRpcServer(shouldBootstrapCluster bool, operatorId string)`

- This method initialize the underlying rpc server used by the raft protocol. If `shouldBootstrapCluster = true` this operator will create a new raft cluster and become the leader.

2 - `TaskConsensusManager.JoinExistingOperatorCluster(joinHttpUrl string, latestBlock uint64)`

- This method must be called after `InitializeRaftRpcServer`

- Operator attempts to join an existing raft cluster. `joinHttpUrl` the the url of another operator operator that is already on the existing cluster.

### Lifecycle of a task

Once the raft server is initialized and the operator has joined a cluster it will either be the leader (only 1 leader per cluster) or a follower. AVS developers can now use the leader as task generators and aggergators.

It is up to the AVS developers to determine the logic for when a task is created on chain but the leader of the current cluster must generate the task on-chain. Once the task is generated on-chain the leader must call `TaskConsensusManager.LeaderSendTaskRequestToFollowers(taskRequest T)` which will be sent to followers and is the entry point to the task lifecycle. Once a task is created it automatically goes through these steps (this is where the callbacks defined by AVS developers will be executed):

1 - The leader sends a message (task request `T`) via the raft protocol to followers

2 - Followers receive this request and then execute the `onTaskRequest[T, K]` callback. This is where follower operators generate an array of task responses `[]K`.

3 - Followers then executre the `onSubmitTaskToLeader[T, K, S]` callback to generate BLS signatures of all their task responses.

4 - Followers submit their task to the leader

5 - The leader parses the followers responses then executes the `onLeaderProcessTaskResponse[K]` callback to generate task digest for the submitted task.

6 - The leader submits the task responseDigest and signed task response to the eigenLayer `blsAggregationService`


### Security considerations on operators joining existing clusters

We added authentication to the `/join` route which is used by operators to join an existing consensus cluster. Operators making the request to join must signed a message with the `latestBlock`. The operators processing the request for a new operator to join will:

- Verify that the resolved address in the signed message is a valid operator (via the `isRegisteredOperator` callback)

- Verify that the block in the signed message is within the last 2 blocks. This prevents old signatures from being reused

## Example AVS using this protocol

### Price Oracle AVS Example

To demonstrate how to use this protocol we created a demo price oracle AVS that aggregates price feed data from multiple trusted on-chain oracle networks (such as chainlink) and allows other contracts to consume that aggregated price feed data.

The EigenShift protocol is used to manage the automatic and trustless rotation of operators acting as task Aggregators. 

Here's how it is integrated:

- Leader Election (Aggregator assignment) and Task Submission: The protocol utilizes Raft to elect a new leader for each task. Every 15 seconds, a task is generated by the current leader operator, and a new operator is elected as the leader upon task submission.

- Operator Setup: The operators are configured to automatically register and join the existing cluster of operators on startup, ensuring they can participate in the consensus protocol.

The types defined in this AVS are:

```go 
// task type T
type PriceUpdateRequest struct {
	FeedName  string
	TaskId    uint32
	LeaderUrl string
}

// task Response type K 
type PriceUpdateTaskResponse struct {
	Price    uint32
	Decimals uint32
	TaskId   uint32
	Source   string
}

// signed TaskResponse type S (used default type)
type SignedTaskResponse[PriceUpdateTaskResponse] struct {
	TaskResponse []PriceUpdateTaskResponse
	BlsSignature []bls.Signature
	OperatorId   sdktypes.OperatorId
}
```

This ensures a robust, decentralized process for task aggregation in the AVS. Check it out here: 
[Price Oracle AVS Example](https://github.com/Robert-H-Leonard/price-oracle-avs).

Here is where the [integration with EigenShift occurs](https://github.com/Robert-H-Leonard/price-oracle-avs/blob/c8e3f45650704bce25eb08a3a3101ea5091a8869/operator/operator.go#L304-L344)

## Why pick the raft protocol for consensus?
Several companies use the Raft protocol for maintaining consensus in distributed systems:

1. **HashiCorp**: Raft is integral to several [HashiCorp products](https://www.hashicorp.com/resources/distributed-consensus-hashicorp-raft) such as Consul, Nomad, and Vault. These tools rely on Raft to manage leader elections, log replication, and ensuring consistency across nodes in a distributed system.

2. **Apache Kafka**: The [Kafka ecosystem](https://developer.confluent.io/learn/kraft/) uses the KRaft protocol, a variant of Raft, to manage metadata and replace the dependency on ZooKeeper. This simplifies Kafka's architecture and improves stability, scalability, and ease of management.

3. **Oracle**: [Oracle's Globally Distributed Database](https://blogs.oracle.com/database/post/raft-replication-in-distributed-23c) employs Raft for replicating data across shards. This ensures consistency and fault tolerance in distributed database environments, providing robust data management even in the presence of failures.

4. **IBM**: [Hyperledger Fabric](https://github.com/IBM/raft-fabric-sample), an open-source blockchain framework developed by IBM, uses the Raft protocol for its ordering service, ensuring that transactions are ordered and committed correctly across the blockchain network.

These examples highlight Raft's versatility and reliability in various distributed systems, ensuring data consistency and fault tolerance across different applications and industries.

We choose to manually integrate with the raft protocol to provide a minimal framework and lightweight raft server with the context of AVS task generation, aggregation and submission.

