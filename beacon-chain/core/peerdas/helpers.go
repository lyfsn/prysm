package peerdas

import (
	"encoding/binary"

	cKzg4844 "github.com/ethereum/c-kzg-4844/bindings/go"

	"github.com/ethereum/go-ethereum/p2p/enode"
	errors "github.com/pkg/errors"
	fieldparams "github.com/prysmaticlabs/prysm/v5/config/fieldparams"
	"github.com/prysmaticlabs/prysm/v5/config/params"
	"github.com/prysmaticlabs/prysm/v5/crypto/hash"
	"github.com/prysmaticlabs/prysm/v5/encoding/bytesutil"
)

const (
	// Number of field elements per extended blob
	fieldElementsPerExtBlob = 2 * cKzg4844.FieldElementsPerBlob

	// Number of columns in the extended blob
	numberOfColumns = fieldElementsPerExtBlob / cKzg4844.BytesPerCell

	// Number of cells in the extended matrix
	extendedMatrixSize = fieldparams.MaxBlobsPerBlock * numberOfColumns
)

type (
	extendedMatrix [extendedMatrixSize]cKzg4844.Cell
	polynomial     [cKzg4844.FieldElementsPerBlob]cKzg4844.Bytes32

	cellCoordinate struct {
		blobIndex uint64
		cellID    uint64
	}
)

var (
	errCustodySubnetCountTooLarge          = errors.New("custody subnet count larger than data column sidecar subnet count")
	errCellNotFound                        = errors.New("cell not found (should never happen)")
	errCurveOrder                          = errors.New("could not set bls curve order as big int")
	errBlsFieldElementNil                  = errors.New("bls field element is nil")
	errBlsFieldElementBiggerThanCurveOrder = errors.New("bls field element higher than curve order")
	errBlsFieldElementDoesNotFit           = errors.New("bls field element does not fit in BytesPerFieldElement")
)

// recoverPolynomial is place holder
// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/polynomial-commitments-sampling.md#recover_polynomial
func recoverPolynomial(cellIds []uint64, cellsBytes []cKzg4844.Cell) (polynomial, error) {
	// I expect the real `recoverPolynomial` function to return on error if not enough (<50%) cells are provided.
	return polynomial{}, nil
}

// custodyColumns retrieves all the column subnets a node should custody.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/das-core.md#helper-functions
func custodyColumns(nodeId enode.ID, custodySubnetCount uint64) (map[uint64]bool, error) {
	// dataColumnSidecarSubnetCount refers to the total number of column subnets used in the protocol.
	dataColumnSidecarSubnetCount := params.BeaconConfig().DataColumnSidecarSubnetCount

	// numberOfColumns refers to the total number of columns in the extended data matrix.
	numberOfColumns := params.BeaconConfig().NumberOfColumns

	if custodySubnetCount > dataColumnSidecarSubnetCount {
		return nil, errCustodySubnetCountTooLarge
	}

	// First, compute the subnet IDs that the node should participate in.
	subnetIds := make(map[uint64]bool, custodySubnetCount)
	i := 0

	for len(subnetIds) < int(custodySubnetCount) {
		nextNodeId := binary.LittleEndian.Uint64(nodeId.Bytes()) + 1
		hashedNextNodeId := hash.Hash(bytesutil.Bytes8(nextNodeId))

		subnetId := binary.LittleEndian.Uint64(hashedNextNodeId[:8]) % dataColumnSidecarSubnetCount

		if _, exists := subnetIds[subnetId]; !exists {
			subnetIds[subnetId] = true
		}

		i++
	}

	columnsPerSubnet := numberOfColumns / dataColumnSidecarSubnetCount

	// Knowing the subnet ID and the number of columns per subnet, select all the columns the node should custody.
	// Columns belonging to the same subnet are contiguous.
	columnIndices := make(map[uint64]bool, custodySubnetCount*columnsPerSubnet)
	for i := uint64(0); i < columnsPerSubnet; i++ {
		for subnetId := range subnetIds {
			columnIndex := dataColumnSidecarSubnetCount*i + subnetId
			columnIndices[columnIndex] = true
		}
	}

	return columnIndices, nil
}

// computeExtendedMatrix computes the extended matrix from the blobs.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/das-core.md#compute_extended_matrix
func computeExtendedMatrix(blobs []cKzg4844.Blob) (*extendedMatrix, error) {
	matrix := &extendedMatrix{}

	for i, blob := range blobs {
		start, stop := i, i+cKzg4844.CellsPerBlob

		// Chunk a non-extended blob into cells representing the corresponding extended blob.
		cells, err := cKzg4844.ComputeCells(&blob)
		if err != nil {
			return nil, errors.Wrap(err, "compute cells for blob")
		}

		// Copy the cells into the extended matrix.
		copy(matrix[start:stop], cells[:])
	}

	return matrix, nil
}

// recoverMatrix recovers the extended matrix from some cells.
// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/das-core.md#recover_matrix
func recoverMatrix(cellFromCoordinate map[cellCoordinate]cKzg4844.Cell, blobCount uint64) (extendedMatrix, error) {
	result := extendedMatrix{}

	for blobIndex := uint64(0); blobIndex < blobCount; blobIndex++ {
		// Filter all cells that belong to the current blob.
		cellIds := make([]uint64, 0, cKzg4844.CellsPerBlob)
		for coordinate := range cellFromCoordinate {
			if coordinate.blobIndex == blobIndex {
				cellIds = append(cellIds, coordinate.cellID)
			}
		}

		// Retrieve cells corresponding to all `cellIds`.
		cellIdsCount := len(cellIds)

		cells := make([]cKzg4844.Cell, 0, cellIdsCount)
		for _, cellId := range cellIds {
			coordinate := cellCoordinate{blobIndex: blobIndex, cellID: cellId}
			cell, ok := cellFromCoordinate[coordinate]
			if !ok {
				return result, errCellNotFound
			}

			cells = append(cells, cell)
		}

		// TODO: The spec says that BLSField is an `uint256`, so we need to convert them to bytes with
		// `bls_field_to_bytes` before we can use them in the `recover_matrix` function. However,
		// `cKzg4844.Cell` is a `[FieldElementsPerCell]Bytes32`, so cells is already a `[][FieldElementsPerCell]Bytes32`.
		// Question: `bls_field_to_bytes`
		// https://github.com/ethereum/consensus-specs/blob/dev/specs/deneb/polynomial-commitments.md#bls_field_to_bytes
		// modulus each element. Is it already the case with `cKzg4844.Cell`?

		// Recover the polynomial.
		fullPolynomial, err := recoverPolynomial(cellIds, cells)
		if err != nil {
			return result, errors.Wrap(err, "recover polynomial")
		}

		// Recover the cells from the polynomial.
		cellsFromFullPolynomial := [cKzg4844.CellsPerBlob]cKzg4844.Cell{}
		for i := 0; i < cKzg4844.CellsPerBlob; i++ {
			var cell cKzg4844.Cell
			copy(cell[:], fullPolynomial[i*cKzg4844.FieldElementsPerCell:(i+1)*cKzg4844.FieldElementsPerCell])
			cells[i] = cell
		}

		// TODO: Once tests are written, try to see if it's possible to avoid at least one copy.
		copy(result[blobIndex*cKzg4844.CellsPerBlob:(blobIndex+1)*cKzg4844.CellsPerBlob], cellsFromFullPolynomial[:])
	}

	return result, nil
}

// https://github.com/ethereum/consensus-specs/blob/dev/specs/_features/eip7594/das-core.md#recover_matrix
// func dataColumnSidecars(signedBlock interfaces.SignedBeaconBlock, blobs []cKzg4844.Blob) ([]ethpb.DataColumnSidecar, error) {
// 	blobsCount := len(blobs)

// 	// Get the signed block header.
// 	signedBlockHeader, err := signedBlock.Header()
// 	if err != nil {
// 		return nil, errors.Wrap(err, "signed block header")
// 	}

// 	// Get the block body.
// 	block := signedBlock.Block()
// 	blockBody := block.Body()

// 	// Compute the KZG commitments inclusion proof.
// 	kzgCommitmentsInclusionProof, err := blocks.MerkleProofKZGCommitments(blockBody)

// 	// Compute cells and proofs.
// 	cells := make([]cKzg4844.Cell, 0, blobsCount)
// 	proofs := make([]cKzg4844.KZGProof, 0, blobsCount)

// 	for _, blob := range blobs {
// 		blobCells, blobProofs, err := cKzg4844.ComputeCellsAndProofs(&blob)
// 		if err != nil {
// 			return nil, errors.Wrap(err, "compute cells and proofs")
// 		}

// 		cells = append(cells, blobCells[:]...)
// 		proofs = append(proofs, blobProofs[:]...)
// 	}
// }
