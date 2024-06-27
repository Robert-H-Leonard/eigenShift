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

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb"
)

const (
	retainSnapshotCount = 2
	raftTimeout         = 5 * time.Second
)

type SignedTaskResponse[K any] struct {
	TaskResponse []K
	BlsSignature []bls.Signature
	OperatorId   sdktypes.OperatorId
}

type onTaskRequest[T any, K any] func(taskRequest T) ([]K, error)                                                                    // Method which is executed when the current leader request a task to be executed to all followers on the network
type onSubmitTaskToLeader[T any, K any, S any] func(taskRequest T, taskResponse []K) (signedResponse S, leaderUrl string, err error) // Method which is executed when a follower operator wants to submit a task to the current leader

// Type T is the task request that is sent from the leader to followers
// Type K is the task response submitted from followers to the leader
// Type S is the bls signed response type submitted to the leader
type PriceFSM[T any, K any, S any] struct {
	RaftDir      string // Directory for operator raft logs
	RaftBind     string // rpc host:port used by the operator for raft protocol
	RaftHttpBind string // http host:port for custom server for custom raft logic
	raft         *raft.Raft
	logger       logging.Logger
	blsKeypair   *bls.KeyPair

	// AVS specific dependencies
	operatorId       sdktypes.OperatorId
	privateKey       *ecdsa.PrivateKey
	onTaskRequestFn  onTaskRequest[T, K]
	onTaskResponseFn onSubmitTaskToLeader[T, K, S]

	// HTTP server dependencies
	httpRaftServer        *Service[K]
	ethClient             eth.Client
	blsAggregationService blsagg.BlsAggregationService
}

func NewConcensusFSM[T any, K any, S any](keyPair *bls.KeyPair, pk *ecdsa.PrivateKey, blsAggregationService blsagg.BlsAggregationService, ethClient eth.Client, logger logging.Logger) *PriceFSM[T, K, S] {
	return &PriceFSM[T, K, S]{
		logger:                logger, // Update logger to be the same as operator                                               // Replace with callbacks
		blsKeypair:            keyPair,
		privateKey:            pk,
		ethClient:             ethClient,
		blsAggregationService: blsAggregationService,
	}
}

func (p *PriceFSM[T, K, S]) ConfigureRaftBindings(rpcUrl string, httpUrl string, fileStorageDirectory string, operatorId [32]byte) {
	p.RaftBind = rpcUrl
	p.RaftDir = fileStorageDirectory
	p.RaftHttpBind = httpUrl
	p.operatorId = operatorId
}

func (p *PriceFSM[T, K, S]) ConfigureTaskCallbacks(onTaskRequestFn onTaskRequest[T, K], onTaskResponseFn onSubmitTaskToLeader[T, K, S]) {
	p.onTaskRequestFn = onTaskRequestFn
	p.onTaskResponseFn = onTaskResponseFn
}

// Operator initializes raft consenses server if enableSingle is set, and there are no existing peers,
// then this node becomes the first node, and therefore leader, of the cluster.
// localID should be the server identifier for this node.
func (p *PriceFSM[T, K, S]) Initialize(enableSingle bool, localId string) error {
	// Setup Raft configuration.
	config := raft.DefaultConfig()
	config.LocalID = raft.ServerID(localId)

	// Setup Raft communication.
	addr, err := net.ResolveTCPAddr("tcp", p.RaftBind)
	if err != nil {
		return err
	}
	transport, err := raft.NewTCPTransport(p.RaftBind, addr, 3, 10*time.Second, os.Stderr)
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
	if enableSingle {
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

func (p *PriceFSM[T, K, S]) InitializeHttpServer(addr string, onLeaderProcessBlsSignedResponse onLeaderProcessBlsSignedResponse[K], isValidOperator isValidOperator, fetchOperatorUrl fetchOperatorUrl) error {
	h := &Service[K]{
		addr:                             addr,
		priceFSM:                         p,
		blsAggregationService:            p.blsAggregationService,
		ethClient:                        p.ethClient,
		onLeaderProcessBlsSignedResponse: onLeaderProcessBlsSignedResponse,
		isValidOperator:                  isValidOperator,
		fetchOperatorUrl:                 fetchOperatorUrl,
		logger:                           p.logger,
	}

	p.logger.Info("Launching raft http server")
	if err := h.Start(); err != nil {
		p.logger.Error("failed to start HTTP service: %s", err.Error())
		return err
	}

	p.logger.Info("Successfully launched raft http server")
	p.httpRaftServer = h

	return nil
}

func (p *PriceFSM[T, K, S]) JoinExistingNetwork(joinAddr, raftAddr, nodeID string, latestBlock uint64) error {

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

	resp, err := http.Post(fmt.Sprintf("http://%s/join", joinAddr), "application-type/json", bytes.NewReader(b))

	if err != nil {
		return err
	}

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("Failed to join raft cluster because:"))
	}

	log.Printf("Joined raft consensus through uri %s", joinAddr)
	defer resp.Body.Close()
	return nil
}

func (p *PriceFSM[T, K, S]) setOperatorId(id sdktypes.OperatorId) {
	p.operatorId = id
}

func (p *PriceFSM[T, K, S]) setOnTaskRequestFn(fn onTaskRequest[T, K]) {
	p.onTaskRequestFn = fn
}

func (p *PriceFSM[T, K, S]) setOnTaskResponseFn(fn onSubmitTaskToLeader[T, K, S]) {
	p.onTaskResponseFn = fn
}

// Join joins a node, identified by nodeID and located at addr, to this store.
// The node must be ready to respond to Raft communications at that address.
func (p *PriceFSM[T, K, S]) Join(nodeID, addr string) error {
	p.logger.Info("received join request for remote node", nodeID, addr)

	configFuture := p.raft.GetConfiguration()
	if err := configFuture.Error(); err != nil {
		p.logger.Info("failed to get raft configuration:", "err", err)
		return err
	}

	for _, srv := range configFuture.Configuration().Servers {
		// If a node already exists with either the joining node's ID or address,
		// that node may need to be removed from the config first.
		if srv.ID == raft.ServerID(nodeID) || srv.Address == raft.ServerAddress(addr) {
			// However if *both* the ID and the address are the same, then nothing -- not even
			// a join operation -- is needed.
			if srv.Address == raft.ServerAddress(addr) && srv.ID == raft.ServerID(nodeID) {
				p.logger.Info("node already member of cluster, ignoring join request", "nodeId", nodeID, "address", addr)
				return nil
			}

			future := p.raft.RemoveServer(srv.ID, 0, 0)
			if err := future.Error(); err != nil {
				return fmt.Errorf("error removing existing node %s at %s: %s", nodeID, addr, err)
			}
		}
	}

	f := p.raft.AddVoter(raft.ServerID(nodeID), raft.ServerAddress(addr), 0, 0)
	if f.Error() != nil {
		return f.Error()
	}
	p.logger.Info("node joined successfully", "nodeId", nodeID, "address", addr)
	return nil
}

func (p *PriceFSM[T, K, S]) IsLeader() (bool, string) {
	leaderURL, _ := p.raft.LeaderWithID()
	return string(leaderURL) == p.RaftBind, string(leaderURL)
}

func (p *PriceFSM[T, K, S]) TriggerElection() {
	p.raft.LeadershipTransfer()
}

func (p *PriceFSM[T, K, S]) SubmitTaskToLeader(request T, responses []K) error {
	signedTaskResponse, leaderUrl, err := p.onTaskResponseFn(request, responses)

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

func (p *PriceFSM[T, K, S]) LeaderSendTaskRequestToFollowers(cmd []byte) error {
	// Only the leader can apply a message that is sent to all followers
	resp := p.raft.Apply(cmd, raftTimeout)

	p.logger.Info("Task request sent to followers")
	return resp.Error()
}

/// Raft protocol integration. The below code is the implementation of the finite state machine used by the raft protocol: https://github.com/hashicorp/raft

type fsmSnapshot struct {
}

func (f *PriceFSM[T, K, S]) Apply(l *raft.Log) interface{} {

	// Leader does not respond to task request from themselves
	leaderURL, _ := f.raft.LeaderWithID()

	if string(leaderURL) == f.RaftBind {
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

	taskResponses, err := f.onTaskRequestFn(request)

	if err != nil {
		log.Printf("Error submitting task: %v", err)
		return nil
	}

	if err := f.SubmitTaskToLeader(request, taskResponses); err != nil {
		f.logger.Info("Failed to submit task response", "err", err)
	}

	return nil
}

func (f *PriceFSM[T, K, S]) Snapshot() (raft.FSMSnapshot, error) {
	return &fsmSnapshot{}, nil
}

// Restore stores the key-value store to a previous state.
func (f *PriceFSM[T, K, S]) Restore(rc io.ReadCloser) error {
	return nil
}

func (f *fsmSnapshot) Persist(sink raft.SnapshotSink) error {
	// No need to persist past task request. All task submissions will be stored on chain once submitted
	return nil
}

func (f *fsmSnapshot) Release() {}
