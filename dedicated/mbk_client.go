package dedicated

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/keyprotect-go-client/dedicated/common"
)

// Native-call headers read by the management service on a master key import.
const (
	headerAuthenticatedAdminCount = "Authenticated-Admin-Count"
	headerIsRotate                = "Is-Rotate"
)

// ************ Master Key state, rotation and record-sync ************

// GetMasterKeyState returns the Master Key state of a crypto unit as held by the
// management service. It does not need a crypto unit session.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetMasterKeyState(cryptoUnitID string) (*CryptoUnitMBKState, error) {
	return keyProtectCryptoUnitAPI.GetMasterKeyStateWithContext(context.Background(), cryptoUnitID)
}

// GetMasterKeyStateWithContext returns the Master Key state of a crypto unit with context
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) GetMasterKeyStateWithContext(ctx context.Context, cryptoUnitID string) (*CryptoUnitMBKState, error) {
	if cryptoUnitID == "" {
		return nil, fmt.Errorf("cryptoUnitID is required")
	}
	var state CryptoUnitMBKState
	if err := keyProtectCryptoUnitAPI.masterKeyRequest(ctx, core.GET, "", cryptoUnitID, "get-master-key-state", nil, &state); err != nil {
		return nil, fmt.Errorf("failed to read master key state for crypto unit %s: %w", cryptoUnitID, err)
	}
	return &state, nil
}

// RotateMasterKey rotates the Master Key of one crypto unit. See RotateMasterKeyOnCryptoUnits.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) RotateMasterKey(cryptoUnitID string, spec *MasterKeyPartsSpec) (*MBKRotationResult, error) {
	return keyProtectCryptoUnitAPI.RotateMasterKeyWithContext(context.Background(), cryptoUnitID, spec)
}

// RotateMasterKeyWithContext rotates the Master Key of one crypto unit with context.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) RotateMasterKeyWithContext(ctx context.Context, cryptoUnitID string, spec *MasterKeyPartsSpec) (*MBKRotationResult, error) {
	results, err := keyProtectCryptoUnitAPI.RotateMasterKeyOnCryptoUnits(ctx, []string{cryptoUnitID}, spec)
	if len(results) == 0 {
		return nil, err
	}
	return &results[0], err
}

// RotateMasterKeyOnCryptoUnits rotates the Master Key of the given crypto units,
// following the 'master-key rotate' CLI flow. The key share files in spec must
// already exist (see GenerateMasterKey), and the client must be connected to
// every crypto unit with enough admins to satisfy the signature threshold.
//
// All units are read first. If their rotation counts differ, every unit is
// rotated onto the highest count (sync mode). A single unit left locked by an
// earlier attempt is diagnosed against the HSM instead of rotated again.
//
// Like the CLI, it stops at the first failing unit and returns the results of
// the units already rotated. Use errors.Is with ErrMBKRotationIncomplete,
// ErrMBKRecordSyncRequired and ErrMBKOutOfSync to pick the recovery step.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) RotateMasterKeyOnCryptoUnits(ctx context.Context, cryptoUnitIDs []string, spec *MasterKeyPartsSpec) ([]MBKRotationResult, error) {
	// This touches durable HSM state and must not be interrupted mid-flight.
	ctx = detachContext(ctx)

	if len(cryptoUnitIDs) == 0 {
		return nil, fmt.Errorf("at least one crypto unit ID is required")
	}
	keyspec, err := validateRotateSpec(spec)
	if err != nil {
		return nil, err
	}

	states := make(map[string]CryptoUnitMBKState, len(cryptoUnitIDs))
	for _, id := range cryptoUnitIDs {
		state, err := keyProtectCryptoUnitAPI.GetMasterKeyStateWithContext(ctx, id)
		if err != nil {
			return nil, err
		}
		states[id] = *state
	}
	plan := planRotation(cryptoUnitIDs, states)
	if plan.syncMode {
		keyProtectCryptoUnitAPI.logger.Warn("crypto units are out of sync; rotating all of them onto rotation count %d", plan.leader.RotationCount)
	}

	results := make([]MBKRotationResult, 0, len(cryptoUnitIDs))
	for _, id := range cryptoUnitIDs {
		res, err := rotateMasterKey(ctx, keyProtectCryptoUnitAPI, keyProtectCryptoUnitAPI.logger, id, keyspec, states[id], plan, len(cryptoUnitIDs))
		if err != nil {
			return results, fmt.Errorf("rotate master key of crypto unit %s: %w", id, err)
		}
		keyProtectCryptoUnitAPI.logger.Info("master key rotated for crypto unit %s: rotation_count=%d, backup_slot=%d, hashed_mk=%s",
			id, res.RotationCount, res.TargetBackupSlot, res.NewHashedMBK)
		results = append(results, *res)
	}
	return results, nil
}

// SyncMasterKeyRecord repairs or seeds the management service record of one
// crypto unit. See SyncMasterKeyRecordOnCryptoUnits.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) SyncMasterKeyRecord(cryptoUnitID string) (*RecordSyncResult, error) {
	return keyProtectCryptoUnitAPI.SyncMasterKeyRecordWithContext(context.Background(), cryptoUnitID)
}

// SyncMasterKeyRecordWithContext repairs or seeds the record of one crypto unit with context
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) SyncMasterKeyRecordWithContext(ctx context.Context, cryptoUnitID string) (*RecordSyncResult, error) {
	results, err := keyProtectCryptoUnitAPI.SyncMasterKeyRecordOnCryptoUnits(ctx, []string{cryptoUnitID})
	if len(results) == 0 {
		return nil, err
	}
	return &results[0], err
}

// SyncMasterKeyRecordOnCryptoUnits implements the 'master-key record-sync' CLI
// command. For each unit it reads the slot hashes from the HSM and either seeds
// the record (hashed_mbk is NULL), repairs it (a single-unit instance whose
// rotation finished on the HSM but was never recorded), or does nothing. The
// client must be connected to every given crypto unit.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) SyncMasterKeyRecordOnCryptoUnits(ctx context.Context, cryptoUnitIDs []string) ([]RecordSyncResult, error) {
	ctx = detachContext(ctx)

	if len(cryptoUnitIDs) == 0 {
		return nil, fmt.Errorf("at least one crypto unit ID is required")
	}
	// The repair flow only applies when the instance has exactly one unit.
	all, _, err := keyProtectCryptoUnitAPI.ListCryptoUnitsWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list crypto units: %w", err)
	}
	cuCount := len(all.CryptoUnits)

	results := make([]RecordSyncResult, 0, len(cryptoUnitIDs))
	for _, id := range cryptoUnitIDs {
		state, err := keyProtectCryptoUnitAPI.GetMasterKeyStateWithContext(ctx, id)
		if err != nil {
			return results, err
		}
		res, err := syncMasterKeyRecord(ctx, keyProtectCryptoUnitAPI, id, *state, cuCount)
		if err != nil {
			return results, fmt.Errorf("record-sync of crypto unit %s: %w", id, err)
		}
		keyProtectCryptoUnitAPI.logger.Info("%s", res.Message)
		results = append(results, *res)
	}
	return results, nil
}

// validateRotateSpec checks the key shares of a rotation and returns the
// comma-separated keyspec. Like the CLI, rotation never generates key shares.
func validateRotateSpec(spec *MasterKeyPartsSpec) (string, error) {
	if spec == nil {
		return "", fmt.Errorf("master key parts spec cannot be nil")
	}
	if len(spec.KeyShareFiles) == 0 {
		return "", fmt.Errorf("KeyShareFiles is required and cannot be empty")
	}
	for _, file := range spec.KeyShareFiles {
		path, _ := splitKeyFileSpec(file)
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("failed to find key share file %s (generate it first with GenerateMasterKey): %w", path, err)
		}
	}
	return strings.Join(spec.KeyShareFiles, ","), nil
}

// ************ mbkOps implementation ************

// rotateRecord calls POST /api/v1/crypto_units/{id}/master_key/rotate.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) rotateRecord(ctx context.Context, cryptoUnitID string, req rotateMBKRequest) (*rotateMBKResponse, error) {
	var resp rotateMBKResponse
	if err := keyProtectCryptoUnitAPI.masterKeyRequest(ctx, core.POST, "/rotate", cryptoUnitID, "rotate-master-key", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// syncRecord calls POST /api/v1/crypto_units/{id}/master_key/record/sync.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) syncRecord(ctx context.Context, cryptoUnitID string, req recordSyncRequest) (*recordSyncResponse, error) {
	var resp recordSyncResponse
	if err := keyProtectCryptoUnitAPI.masterKeyRequest(ctx, core.POST, "/record/sync", cryptoUnitID, "record-sync-master-key", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// importKey imports the key shares into one slot of the crypto unit. The
// authenticated admin count and the rotate flag travel as headers that the
// management service reads.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) importKey(ctx context.Context, cryptoUnitID, keyspec string, slot, authenticatedAdmins int, isRotate bool) error {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return err
	}
	action := "import-master-key"
	if isRotate {
		action = "rotate-master-key"
	}
	headers := copyHeaders(createHeadersfromContext(ctx, action, keyProtectCryptoUnitAPI.instanceID))
	if authenticatedAdmins > 0 {
		headers[headerAuthenticatedAdminCount] = strconv.Itoa(authenticatedAdmins)
	}
	if isRotate {
		headers[headerIsRotate] = "true"
	}
	return callImportMasterKey(sessionID, keyspec, slot, headers)
}

// listSlots reads the slot hashes and the slot 3 generation date from the HSM.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) listSlots(cryptoUnitID string) (map[int]string, time.Time, error) {
	sessionID, err := keyProtectCryptoUnitAPI.getSessionID(cryptoUnitID)
	if err != nil {
		return nil, time.Time{}, err
	}
	raw, err := callListMasterKeys(sessionID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to list master keys of crypto unit %s: %w", cryptoUnitID, err)
	}
	return parseSlotHashes(raw)
}

// authenticatedAdmins returns how many admins authenticated on the session of the unit.
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) authenticatedAdmins(cryptoUnitID string) (int, error) {
	sess, ok := keyProtectCryptoUnitAPI.sessions.get(cryptoUnitID)
	if !ok {
		return 0, fmt.Errorf("not connected to crypto unit %s: call CreateCryptoUnitSession first", cryptoUnitID)
	}
	users, err := keyProtectCryptoUnitAPI.ListUsers(cryptoUnitID)
	if err != nil {
		return 0, err
	}
	return countAuthenticatedAdmins(users, sess.Username), nil
}

// ************ management service REST helper ************

// masterKeyRequest calls /api/v1/crypto_units/{id}/master_key<suffix> and
// decodes a JSON response into out (an empty body leaves out untouched).
func (keyProtectCryptoUnitAPI *KeyProtectCryptoUnitAPI) masterKeyRequest(ctx context.Context, method, suffix, cryptoUnitID, action string, body, out any) error {
	builder := core.NewRequestBuilder(method).WithContext(ctx)
	_, err := builder.ResolveRequestURL(
		keyProtectCryptoUnitAPI.Service.Options.URL,
		`/api/v1/crypto_units/{crypto_unit_id}/master_key`+suffix,
		map[string]string{"crypto_unit_id": cryptoUnitID},
	)
	if err != nil {
		return core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
	}

	headers := copyHeaders(createHeadersfromContext(ctx, action, keyProtectCryptoUnitAPI.instanceID))
	headers["Crypto-Unit-ID"] = cryptoUnitID
	for name, value := range headers {
		builder.AddHeader(name, value)
	}
	builder.AddHeader("Accept", "application/json")
	if body != nil {
		if _, err := builder.SetBodyContentJSON(body); err != nil {
			return core.SDKErrorf(err, "", "set-body-error", common.GetComponentInfo())
		}
	}

	request, err := builder.Build()
	if err != nil {
		return core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
	}

	// The SDK decodes a JSON response body into the result it is given.
	var raw json.RawMessage
	if _, err := keyProtectCryptoUnitAPI.Service.Request(request, &raw); err != nil {
		return core.SDKErrorf(err, "", "request-error", common.GetComponentInfo())
	}

	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("failed to parse the %s response: %w", action, err)
		}
	}
	return nil
}

// copyHeaders returns a copy so per-call headers (Is-Rotate, Crypto-Unit-ID)
// never leak into a header map shared through the caller's context.
func copyHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+2)
	for k, v := range in {
		out[k] = v
	}
	return out
}
