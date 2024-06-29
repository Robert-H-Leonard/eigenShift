package taskconsensus

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/Layr-Labs/eigensdk-go/chainio/clients/eth"
	"github.com/Layr-Labs/eigensdk-go/crypto/bls"
	"github.com/Layr-Labs/eigensdk-go/logging"
	blsagg "github.com/Layr-Labs/eigensdk-go/services/bls_aggregation"
	sdktypes "github.com/Layr-Labs/eigensdk-go/types"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
)

const (
	retainSnapshotCount = 2
	raftTimeout         = 5 * time.Second
)

// We provide a default signed response type (S) where the type K is the task response type that followers submit to the leader
type SignedTaskResponse[K any] struct {
	TaskResponse []K
	BlsSignature []bls.Signature
	OperatorId   sdktypes.OperatorId
}

type OperatorRaftConfig struct {
	// Http url that the operator must provide and expose to create the needed custom http server
	HttpUrl string
	// Rpc url that the operator must provide and expose to connect to a raft cluster
	RpcUrl string
	// Path to directory where raft protocol distributed replicated log is stored
	FileStorageDirectory string
	OperatorId           sdktypes.OperatorId
}

// Type T is the task request that is sent from the leader to followers
// Type K is the task response submitted from followers to the leader
// Type S is the bls signed response type submitted to the leader
//
//	--------------------------------------------------------------
//
// The task engine provides a minimal framework where AVS developers define the functionallity of task generation, aggregation and on-chain submission.
// This engine uses the raft protcol and ensures that there can only ever be 1 leader.
type TaskConsensusEngine[T any, K any, S any] struct {
	RaftDir      string // Directory for operator raft logs
	RaftRpcBind  string // rpc host:port used by the operator for raft protocol
	RaftHttpBind string // http host:port for custom server for custom raft logic
	raft         *raft.Raft
	logger       logging.Logger
	blsKeypair   *bls.KeyPair

	// AVS specific dependencies
	operatorId sdktypes.OperatorId
	privateKey *ecdsa.PrivateKey
	callbacks  TaskConsensusCallbacks[T, K, S]

	// HTTP server dependencies
	httpRaftServer        *Service[K]
	ethClient             eth.Client
	blsAggregationService blsagg.BlsAggregationService
}

// Callbacks that must be implemented by AVS developers
// Type T is the task request type is sent from the leader to followers
// Type K is the task response type from followers to the leader
// Type S is the bls signed response type submitted to the leader
type TaskConsensusCallbacks[T any, K any, S any] struct {
	// Method that is triggered when a follower receives a task request (T) from the current leader. The follower resonse (K) is returned
	OnTaskRequestFn onTaskRequest[T, K]

	// Method that is triggered when a follower want to sign their task response (K) with a BLS signature and submit that response to the leader
	OnTaskResponseFn onSubmitTaskToLeader[T, K, S]

	// Method that is used to verify that a given operator address
	IsValidOperator isRegisteredOperator

	// Method that is triggered when the current leader receives a task response (K) from a follower and generatesa taskDigest
	// The task digest is essentially an unsigned hash of the task fileds and values
	OnLeaderProcessTaskResponse onLeaderProcessTaskResponse[K]

	// Method that fetches the raftRpc and http urls for a given operator address
	// It is up to the AVS developers to implement how operator urls are discovered by other operators
	FetchOperatorUrl fetchOperatorUrl
}

// Callback type defs
// Type T is the task request type is sent from the leader to followers
// Type K is the task response type from followers to the leader
// Type S is the bls signed response type submitted to the leader
type onTaskRequest[T any, K any] func(taskRequest T) (taskResponses []K, err error)
type onSubmitTaskToLeader[T any, K any, S any] func(taskRequest T, taskResponse []K) (signedResponse S, leaderUrl string, err error)
type onLeaderProcessTaskResponse[K any] func(taskResponse K, w http.ResponseWriter) (taskIndex uint32, taskResponseDigest [32]byte)
type isRegisteredOperator func(operatorAddress common.Address) (bool, error)
type fetchOperatorUrl func(operatorAddress common.Address) (OperatorRaftConfig, error)

// Method used by operators already on an existing raft cluster to add new operators to the cluster
// The http server requires operators to sign a message and ensures only operators bootstrap or join existing raft clusters
type onNewOperatorJoiningCluster func(operatorId, addr string) error

// This represents an instance of the task engine once it is initiatied and all the methods avalible to developers when building their AVS
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
}

func NewAVSConcensusEngine[T any, K any, S any](keyPair *bls.KeyPair, pk *ecdsa.PrivateKey, blsAggregationService blsagg.BlsAggregationService, ethClient eth.Client, logger logging.Logger, callbacks TaskConsensusCallbacks[T, K, S], operatorRaftConfig OperatorRaftConfig) (TaskConsensusManager[T, K, S], error) {
	taskEngine := &TaskConsensusEngine[T, K, S]{
		logger:                logger, // Update logger to be the same as operator                                               // Replace with callbacks
		blsKeypair:            keyPair,
		privateKey:            pk,
		ethClient:             ethClient,
		blsAggregationService: blsAggregationService,
		RaftRpcBind:           operatorRaftConfig.RpcUrl,
		RaftHttpBind:          operatorRaftConfig.HttpUrl,
		RaftDir:               operatorRaftConfig.FileStorageDirectory,
		operatorId:            operatorRaftConfig.OperatorId,
		callbacks:             callbacks,
	}

	// Configure http server
	taskEngine.httpRaftServer = &Service[K]{
		addr:                        operatorRaftConfig.OperatorId.LogValue().String(),
		onNewOperatorJoiningCluster: taskEngine.Join,
		blsAggregationService:       blsAggregationService,
		ethClient:                   ethClient,
		onLeaderProcessTaskResponse: callbacks.OnLeaderProcessTaskResponse,
		isValidOperator:             callbacks.IsValidOperator,
		fetchOperatorUrl:            callbacks.FetchOperatorUrl,
		logger:                      logger,
	}

	logger.Info("Launching raft http server")
	if err := taskEngine.httpRaftServer.Start(); err != nil {
		logger.Error("failed to start HTTP service: %s", err.Error())
		return nil, err
	}

	logger.Info("Successfully launched raft http server")

	var engine TaskConsensusManager[T, K, S] = taskEngine

	return engine, nil
}

// Operator initializes raft consenses server if enableSingle is set, and there are no existing peers,
// then this node becomes the first node, and therefore leader, of the cluster.
// operatorId should be the server identifier for this node.
func (p *TaskConsensusEngine[T, K, S]) InitializeRaftRpcServer(shouldBootstrapCluster bool, operatorId string) error {
	// Setup Raft configuration.
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(operatorId)

	// Setup Raft communication.
	addr, err := net.ResolveTCPAddr("tcp", p.RaftRpcBind)
	if err != nil {
		return err
	}
	transport, err := raft.NewTCPTransport(p.RaftRpcBind, addr, 3, 10*time.Second, os.Stderr)
	if err != nil {
		return err
	}

	// Create the snapshot store. This allows the Raft to truncate the log.
	snapshots, err := raft.NewFileSnapshotStore(p.RaftDir, retainSnapshotCount, os.Stderr)
	if err != nil {
		return fmt.Errorf("file snapshot store: %s", err)
	}

	// Create the log store and stable store using BoltDB in memory key value store
	var logStore raft.LogStore
	var stableStore raft.StableStore

	boltDB, err := raftboltdb.New(raftboltdb.Options{
		Path: filepath.Join(p.RaftDir, "raft.db"),
	})
	if err != nil {
		return fmt.Errorf("new bbolt store: %s", err)
	}

	logStore = boltDB
	stableStore = boltDB

	// Instantiate the Raft systems.
	p.logger.Info("Launching raft rpc server")
	ra, err := raft.NewRaft(config, (raft.FSM)(p), logStore, stableStore, snapshots, transport)
	if err != nil {
		return fmt.Errorf("new raft: %s", err)
	}
	p.raft = ra

	// If only node and not joining an existing raft network bootstrap the network
	if shouldBootstrapCluster {
		configuration := raft.Configuration{
			Servers: []raft.Server{
				{
					ID:      config.LocalID,
					Address: transport.LocalAddr(),
				},
			},
		}
		ra.BootstrapCluster(configuration)
	}
	return nil
}

// Operator attempts to join an existing raft cluster of operators.
// joinHttpUrl string: The url of an operator that is already connected to an existing raft cluster. It is up to the AVS developer to implement a way for urls to be discovered
// latestBlock uint64: the latest block the operator is aware of.
func (p *TaskConsensusEngine[T, K, S]) JoinExistingOperatorCluster(joinHttpUrl string, latestBlock uint64) error {

	// Sign message with latest block and send to leader
	data := []byte(strconv.FormatUint(latestBlock, 10))
	hash := crypto.Keccak256Hash(data)

	message, err := crypto.Sign(hash.Bytes(), p.privateKey)

	if err != nil {
		return err
	}

	b, err := json.Marshal(map[string]string{"signedMessage": base64.StdEncoding.EncodeToString(message[:]), "messageHash": base64.StdEncoding.EncodeToString(hash.Bytes()[:]), "blockNumber": strconv.FormatUint(latestBlock, 10)})

	if err != nil {
		return err
	}

	resp, err := http.Post(fmt.Sprintf("http://%s/join", joinHttpUrl), "application-type/json", bytes.NewReader(b))

	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("Failed to join raft cluster because:"))
	}

	log.Printf("Joined raft consensus through uri %s", joinHttpUrl)
	defer resp.Body.Close()
	return nil
}

// Checks if an operator is the current leader of the raft cluster it is connected to
// This can be used to gate operator functionallity by leaders and followers
func (p *TaskConsensusEngine[T, K, S]) IsLeader() (bool, string) {
	leaderURL, _ := p.raft.LeaderWithID()
	return string(leaderURL) == p.RaftRpcBind, string(leaderURL)
}

// Only the current leader can trigger a new election manually
// The raft protocol handles automatic re-elections is a leader goes offline
func (p *TaskConsensusEngine[T, K, S]) TriggerElection() {
	p.raft.LeadershipTransfer()
}

func (p *TaskConsensusEngine[T, K, S]) LeaderSendTaskRequestToFollowers(taskRequest T) error {
	cmd, err := json.Marshal(taskRequest)

	if err != nil {
		p.logger.Error("Failed to request task", "err", err)
	}
	// Only the leader can apply a message that is sent to all followers
	resp := p.raft.Apply(cmd, raftTimeout)

	p.logger.Info("Task request sent to followers")
	return resp.Error()
}

///////////// Internal consensus engine methods ///////////////

// Join joins a node, identified by nodeID and located at addr, to this store.
// The node must be ready to respond to Raft communications at that address.
func (p *TaskConsensusEngine[T, K, S]) Join(operatorId, addr string) error {
	p.logger.Info("received join request for remote node", operatorId, addr)

	configFuture := p.raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		p.logger.Info("failed to get raft configuration:", "err", err)
		return err
	}

	for _, srv := range configFuture.Configuration().Servers {
		// If a node already exists with either the joining node's ID or address,
		// that node may need to be removed from the config first.
		if srv.ID == raft.ServerID(operatorId) || srv.Address == raft.ServerAddress(addr) {
			// However if *both* the ID and the address are the same, then nothing -- not even
			// a join operation -- is needed.
			if srv.Address == raft.ServerAddress(addr) && srv.ID == raft.ServerID(operatorId) {
				p.logger.Info("node already member of cluster, ignoring join request", "nodeId", operatorId, "address", addr)
				return nil
			}

			future := p.raft.RemoveServer(srv.ID, 0, 0)
			if err := future.Error(); err != nil {
				return fmt.Errorf("error removing existing node %s at %s: %s", operatorId, addr, err)
			}
		}
	}

	f := p.raft.AddVoter(raft.ServerID(operatorId), raft.ServerAddress(addr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	p.logger.Info("node joined successfully", "nodeId", operatorId, "address", addr)
	return nil
}

func (p *TaskConsensusEngine[T, K, S]) SubmitTaskToLeader(request T, responses []K) error {
	signedTaskResponse, leaderUrl, err := p.callbacks.OnTaskResponseFn(request, responses)

	b, err := json.Marshal(signedTaskResponse)
	if err != nil {
		return err
	}
	resp, err := http.Post(fmt.Sprintf("http://%s/submitAvsTask", leaderUrl), "application-type/json", bytes.NewReader(b))
	if err != nil {
		return err
	}

	log.Printf("Submitted task to %s:", leaderUrl)
	defer resp.Body.Close()
	return nil
}

/// Raft protocol integration. The below code is the implementation of the finite state machine used by the raft protocol: https://github.com/hashicorp/raft

type fsmSnapshot struct {
}

func (f *TaskConsensusEngine[T, K, S]) Apply(l *raft.Log) interface{} {

	// Leader does not respond to task request from themselves
	leaderURL, _ := f.raft.LeaderWithID()

	if string(leaderURL) == f.RaftRpcBind {
		return nil
	}

	lastAppliedIndex := f.raft.AppliedIndex()

	if l.Index < lastAppliedIndex {
		return nil // No need to replay previous logs
	}

	var request T
	if err := json.Unmarshal(l.Data, &request); err != nil {
		panic(fmt.Sprintf("failed to unmarshal command: %s", err.Error()))
	}

	taskResponses, err := f.callbacks.OnTaskRequestFn(request)

	if err != nil {
		log.Printf("Error submitting task: %v", err)
		return nil
	}

	if err := f.SubmitTaskToLeader(request, taskResponses); err != nil {
		f.logger.Info("Failed to submit task response", "err", err)
	}

	return nil
}

func (f *TaskConsensusEngine[T, K, S]) Snapshot() (raft.FSMSnapshot, error) {
	return &fsmSnapshot{}, nil
}

// Restore stores the key-value store to a previous state.
func (f *TaskConsensusEngine[T, K, S]) Restore(rc io.ReadCloser) error {
	return nil
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	// No need to persist past task request. All task submissions will be stored on chain once submitted
	return nil
}

func (f *fsmSnapshot) Release() {}
