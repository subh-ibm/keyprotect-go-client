package dedicated

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Master Key slots. Slot 3 is the active slot; slots 8-12 hold backups.
const (
	MBKSlotActive = 3
	MBKSlotBackup = 8
)

// rotationSlots is the fixed cycle of backup slots used by rotation, indexed by
// rotation_count % 5, so consecutive rotations never overwrite the same slot.
var rotationSlots = [5]int{9, 10, 11, 12, 8}

// backupSlots are all slots that may hold a backup Master Key.
var backupSlots = []int{8, 9, 10, 11, 12}

// hsmGenerationDateLayout is the date+time format of the HSM master key list output.
const hsmGenerationDateLayout = "2006/01/02 15:04:05"

// Actions reported by SyncMasterKeyRecord.
const (
	RecordSyncActionSeeded   = "seeded"   // hashed_mbk written for the first time
	RecordSyncActionRepaired = "repaired" // DB updated after the HSM rotation completed
	RecordSyncActionNoOp     = "no-op"    // nothing to repair
)

// Errors returned by rotation and record-sync. Use errors.Is to test for them.
var (
	// ErrMBKRotationIncomplete means the HSM state could not be confirmed or is
	// partially updated. Running rotate again completes or recovers it.
	ErrMBKRotationIncomplete = errors.New("master key rotation could not be completed or confirmed; re-run the rotation")

	// ErrMBKRecordSyncRequired means the rotation finished on the HSM but the
	// database record was not updated. Run SyncMasterKeyRecord to repair it.
	ErrMBKRecordSyncRequired = errors.New("master key rotation completed on the hardware but the database record is out of date; run record-sync")

	// ErrMBKOutOfSync means the crypto units were not all updated, so their
	// rotation counts differ. Re-running rotate syncs all crypto units.
	ErrMBKOutOfSync = errors.New("master key rotation aborted; the crypto units are not in sync, re-run the rotation to sync them")

	// ErrMBKSeedFailed is returned as a warning by ImportMasterKey when the
	// import succeeded but the database record could not be seeded. Run
	// SyncMasterKeyRecord to repair it; rotation is blocked until then.
	ErrMBKSeedFailed = errors.New("master key import succeeded but the database record could not be updated; run record-sync")
)

// CryptoUnitMBKState is the Master Key state of a crypto unit held by the
// management service (GET /api/v1/crypto_units/{id}/master_key).
type CryptoUnitMBKState struct {
	// HashedMBK is nil when the DB column is NULL (not yet seeded).
	HashedMBK             *string    `json:"hashed_MK"`
	RotationCount         int        `json:"rotation_count"`
	LastRotationTimestamp *time.Time `json:"last_rotation_timestamp,omitempty"`
	AllowFrequentRotation *bool      `json:"allow_frequent_rotation,omitempty"`
	LastRecryptSlotNo     *int       `json:"last_recrypt_slot_no,omitempty"`
	IsImportSuccessful    *bool      `json:"is_import_successful,omitempty"`
	AllowImport           *bool      `json:"allow_import,omitempty"`
	// BackupSlotHash and BackupSlotNumber describe the backup slot of the
	// current rotation_count. Empty / zero when no backup record exists.
	BackupSlotHash   string `json:"backup_slot_hash,omitempty"`
	BackupSlotNumber int    `json:"backup_slot_number,omitempty"`
}

// MBKRotationResult is the outcome of rotating the Master Key of one crypto unit.
type MBKRotationResult struct {
	CryptoUnitID     string
	RotationCount    int
	TargetBackupSlot int
	NewHashedMBK     string
}

// RecordSyncResult is the outcome of SyncMasterKeyRecord for one crypto unit.
type RecordSyncResult struct {
	CryptoUnitID  string
	Action        string // one of the RecordSyncAction constants
	Message       string
	RotationCount int
}

// rotateMBKRequest is the body of POST .../master_key/rotate.
//
// Preflight: empty body, CMS validates and locks the unit (allow_import=false).
// Commit: NewHashedMBK and SlotHashes after both HSM imports succeeded.
// Abort: Aborted=true only releases the preflight lock.
// Sync: SkipValidation=true with BaseRotationCount lands every unit on the same count.
type rotateMBKRequest struct {
	NewHashedMBK      string            `json:"newHashedMK"`
	SlotHashes        map[string]string `json:"slotHashes"`
	Aborted           bool              `json:"aborted,omitempty"`
	SkipValidation    bool              `json:"skipValidation,omitempty"`
	BaseRotationCount *int              `json:"baseRotationCount,omitempty"`
}

type rotateMBKResponse struct {
	RotationCount    int    `json:"rotationCount"`
	TargetBackupSlot int    `json:"targetBackupSlot"`
	NewHashedMBK     string `json:"newHashedMK"`
}

// recordSyncScenario matches the CMS constants (1 = repair, 2 = seed).
type recordSyncScenario int

const (
	recordSyncScenarioRepair recordSyncScenario = 1
	recordSyncScenarioSeed   recordSyncScenario = 2
)

// recordSyncRequest is the body of POST .../master_key/record/sync.
type recordSyncRequest struct {
	Scenario       recordSyncScenario `json:"scenario"`
	SlotHashes     map[int]string     `json:"slotHashes"`
	GenerationDate time.Time          `json:"generationDate"`
	RotationCount  int                `json:"rotationCount,omitempty"`
	OldHashedMBK   string             `json:"oldHashedMBK,omitempty"`
}

type recordSyncResponse struct {
	RotationCount int    `json:"rotationCount"`
	Message       string `json:"message"`
}

// targetBackupSlot returns the backup slot written by the next rotation.
func targetBackupSlot(rotationCount int) int {
	if rotationCount < 0 {
		rotationCount = 0
	}
	return rotationSlots[rotationCount%len(rotationSlots)]
}

// isFreshRotationState reports allow_import=false AND is_import_successful=false:
// the preflight lock is set but no rotation was committed.
func isFreshRotationState(s CryptoUnitMBKState) bool {
	return s.AllowImport != nil && !*s.AllowImport &&
		s.IsImportSuccessful != nil && !*s.IsImportSuccessful
}

// isImportSuccessfulOrNil reports is_import_successful is NULL or true.
func isImportSuccessfulOrNil(s CryptoUnitMBKState) bool {
	return s.IsImportSuccessful == nil || *s.IsImportSuccessful
}

// parseSlotHashes parses the master key list output into slot -> key check
// value, plus the slot 3 generation date. Each data row is:
//
//	slot name len algo type k YYYY/MM/DD HH:MM:SS keyCheckValue
func parseSlotHashes(raw string) (map[int]string, time.Time, error) {
	hashes := make(map[int]string)
	var slot3Date time.Time
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "slot") || strings.HasPrefix(line, "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		slot, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		hashes[slot] = fields[8]
		if slot == MBKSlotActive {
			d, err := time.Parse(hsmGenerationDateLayout, fields[6]+" "+fields[7])
			if err != nil {
				return nil, time.Time{}, fmt.Errorf("failed to parse slot 3 generation date %q %q: %w", fields[6], fields[7], err)
			}
			slot3Date = d
		}
	}
	if len(hashes) == 0 {
		return nil, time.Time{}, errors.New("could not parse any master key slots from the HSM list output")
	}
	return hashes, slot3Date, nil
}

// countAuthenticatedAdmins counts the users of the session that hold the admin
// permission. authenticated is the comma-joined user list of the session.
func countAuthenticatedAdmins(users []UserInfo, authenticated string) int {
	names := map[string]struct{}{}
	for _, n := range strings.Split(authenticated, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names[n] = struct{}{}
		}
	}
	count := 0
	for _, u := range users {
		if u.Permissions != AdminPermission {
			continue
		}
		if _, ok := names[u.Username]; ok {
			count++
		}
	}
	return count
}

// rotationPlan is the path chosen from the Master Key state of all crypto units.
type rotationPlan struct {
	// syncMode: rotation counts differ. Every unit is rotated as if its count
	// were leader.RotationCount-1, with validation skipped.
	syncMode bool
	leader   CryptoUnitMBKState
	// singlePartial: exactly one unit, locked with no committed rotation.
	singlePartial bool
}

// planRotation decides how to rotate the given units from their states.
func planRotation(ids []string, states map[string]CryptoUnitMBKState) rotationPlan {
	var p rotationPlan
	if len(ids) == 0 {
		return p
	}
	p.leader = states[ids[0]]
	for _, id := range ids[1:] {
		s := states[id]
		if s.RotationCount != p.leader.RotationCount {
			p.syncMode = true
		}
		if s.RotationCount > p.leader.RotationCount {
			p.leader = s
		}
	}
	if p.syncMode {
		// The first loop may have missed a unit surpassed after a leader change.
		for _, id := range ids {
			if s := states[id]; s.RotationCount > p.leader.RotationCount {
				p.leader = s
			}
		}
		return p
	}
	p.singlePartial = len(ids) == 1 && isFreshRotationState(states[ids[0]])
	return p
}

// mbkOps is what the rotate and record-sync flows need from the client. It is
// an interface so the flows can be tested without an HSM or management service.
type mbkOps interface {
	// rotateRecord calls POST .../master_key/rotate.
	rotateRecord(ctx context.Context, cuID string, req rotateMBKRequest) (*rotateMBKResponse, error)
	// syncRecord calls POST .../master_key/record/sync.
	syncRecord(ctx context.Context, cuID string, req recordSyncRequest) (*recordSyncResponse, error)
	// importKey imports the key shares into a slot of the unit.
	importKey(ctx context.Context, cuID, keyspec string, slot, authenticatedAdmins int, isRotate bool) error
	// listSlots reads slot -> hash and the slot 3 generation date from the HSM.
	listSlots(cuID string) (map[int]string, time.Time, error)
	// authenticatedAdmins returns the number of authenticated admins of the session.
	authenticatedAdmins(cuID string) (int, error)
}

// seedMasterKeyRecord reads the slot hashes from the HSM and seeds the database
// record of the unit (scenario 2). rotation_count is not touched by CMS.
func seedMasterKeyRecord(ctx context.Context, ops mbkOps, cuID string) (*recordSyncResponse, error) {
	hashes, genDate, err := ops.listSlots(cuID)
	if err != nil {
		return nil, err
	}
	return ops.syncRecord(ctx, cuID, recordSyncRequest{
		Scenario:       recordSyncScenarioSeed,
		SlotHashes:     hashes,
		GenerationDate: genDate,
	})
}
