package taskconsensus

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/Layr-Labs/eigensdk-go/chainio/clients/eth"
	"github.com/Layr-Labs/eigensdk-go/logging"
	blsagg "github.com/Layr-Labs/eigensdk-go/services/bls_aggregation"
	"github.com/ethereum/go-ethereum/crypto"
)

// Type K is the task response submitted from followers to the leader
type Service[K any] struct {
	operatorHttpUrl string
	ln              net.Listener
	logger          logging.Logger

	blsAggregationService       blsagg.BlsAggregationService
	ethClient                   eth.Client
	onLeaderProcessTaskResponse onLeaderProcessTaskResponse[K]
	isValidOperator             isRegisteredOperator
	fetchOperatorUrl            fetchOperatorUrl
	onNewOperatorJoiningCluster onNewOperatorJoiningCluster
}

// New returns an uninitialized HTTP service.
func NewService[K any](addr string, onNewOperatorJoiningCluster onNewOperatorJoiningCluster, blsAggregationService blsagg.BlsAggregationService, ethClient eth.Client) *Service[K] {
	return &Service[K]{
		operatorHttpUrl:             addr,
		onNewOperatorJoiningCluster: onNewOperatorJoiningCluster,
		blsAggregationService:       blsAggregationService,
		ethClient:                   ethClient,
	}
}

// Start starts the service.
func (s *Service[K]) Start() error {
	server := http.Server{
		Handler: s,
	}

	log.Println("Initializing http server")

	ln, err := net.Listen("tcp", s.operatorHttpUrl)
	if err != nil {
		return err
	}
	s.ln = ln

	http.Handle("/", s)

	go func() {
		err := server.Serve(s.ln)
		if err != nil {
			log.Fatalf("HTTP serve: %s", err)
		}
	}()

	log.Printf("Http server started\n")

	return nil
}

// ServeHTTP allows Service to serve HTTP requests.
func (s *Service[K]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/submitAvsTask" {
		s.handleTaskSubmittionToBlsService(w, r)
	} else if r.URL.Path == "/join" {
		s.handleJoin(w, r)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
}

// Operators attempting to join must sign a message with the latest block they are aware of.
// This endpoint validates the signature is from a valid operator + the latest block is within the last 2 blocks
func (s *Service[K]) handleJoin(w http.ResponseWriter, r *http.Request) {
	m := map[string]string{}
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if len(m) != 3 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signedMessage, ok := m["signedMessage"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	messageHash, ok := m["messageHash"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	blockNumber, ok := m["blockNumber"]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	signedMessageBytes, err := base64.StdEncoding.DecodeString(signedMessage)

	if err != nil {
		s.logger.Warn("Failed to decode signed message", "err", err)
	}

	messageBytes, err := base64.StdEncoding.DecodeString(messageHash)

	if err != nil {
		s.logger.Warn("Failed to decode message hash", "err", err)
	}

	sigPublicKey, err := crypto.SigToPub(messageBytes, signedMessageBytes)

	if err != nil {
		s.logger.Warn("Failed to parse operator signature", "err", err)
	}

	isValidOperator, err := s.isValidOperator(crypto.PubkeyToAddress(*sigPublicKey))

	if !isValidOperator || err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Resolved address is not a valid operator"))
		return
	}

	validOperatorUrls, err := s.fetchOperatorUrl(crypto.PubkeyToAddress(*sigPublicKey))

	if err != nil {
		s.logger.Warn("Failed to fetch url for operator", "address", crypto.PubkeyToAddress(*sigPublicKey), "error", err)
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Resolved address is not a valid operator"))
		return
	} else {
		s.logger.Warn("Resolved operator address joining raft cluster is", "address", crypto.PubkeyToAddress(*sigPublicKey))
	}

	data := []byte(blockNumber)
	hash := crypto.Keccak256Hash(data)
	resolvedBlockNumberHash := base64.StdEncoding.EncodeToString(hash.Bytes()[:])

	if messageHash != resolvedBlockNumberHash {
		s.logger.Warn("Blocknumber hash does not match block number")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Blocknumber hash does not match block number"))
		return
	}

	// Verify block number is within last 2 blocks to protect against stale signatures
	latestBlock, _ := s.ethClient.BlockNumber(context.Background())

	blockAsInt, _ := strconv.ParseUint(blockNumber, 10, 64)

	if blockAsInt != latestBlock && blockAsInt != latestBlock-1 {
		s.logger.Warn("Blocknumber in signature is to old")
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Blocknumber in signature is to old"))
		return
	}

	nodeID := crypto.PubkeyToAddress(*sigPublicKey).String()

	if err := s.onNewOperatorJoiningCluster(nodeID, validOperatorUrls.RpcUrl); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Service[K]) handleTaskSubmittionToBlsService(w http.ResponseWriter, r *http.Request) { // handle task submission with 2 generic + 1 callback

	var signedResponse SignedTaskResponse[K]

	if err := json.NewDecoder(r.Body).Decode(&signedResponse); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Submit each price feed source seperatly
	s.logger.Info("Preparing to submit bls signatures")
	for i, task := range signedResponse.TaskResponse {
		taskIndex, taskResponseDigest := s.onLeaderProcessTaskResponse(task, w)

		signature := signedResponse.BlsSignature[i]

		err := s.blsAggregationService.ProcessNewSignature(
			context.Background(), taskIndex, taskResponseDigest,
			&signature, signedResponse.OperatorId,
		)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		s.logger.Info("Submitted bls signature to aggregation service",
			"taskId", taskIndex,
			"operatorId", signedResponse.OperatorId.LogValue().String(),
		)
	}
}
