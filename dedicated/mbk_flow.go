package dedicated

import (
	"context"
	"fmt"
	"strconv"

	"github.com/IBM/go-sdk-core/v5/core"
)

// abortRotation releases the preflight lock (allow_import=TRUE) after a failure
// where nothing was written to the HSM. A failure to release is only logged,
// because the primary error is the one the caller needs.
func abortRotation(ctx context.Context, ops mbkOps, logger core.Logger, cuID string) {
	if _, err := ops.rotateRecord(ctx, cuID, rotateMBKRequest{Aborted: true}); err != nil {
		logger.Warn("failed to reset the import lock of crypto unit %s: %s", cuID, err)
	}
}

// rotateMasterKey rotates the Master Key of one crypto unit. It follows the
// CLI 'master-key rotate' flow:
//
//	preflight (CMS lock) -> import backup slot -> import slot 3 -> read back
//	and verify -> commit to CMS.
//
// state is the unit's Master Key state read before any unit was touched, plan
// the path chosen for all units, and cuCount the number of units being rotated.
func rotateMasterKey(ctx context.Context, ops mbkOps, logger core.Logger, cuID, keyspec string, state CryptoUnitMBKState, plan rotationPlan, cuCount int) (*MBKRotationResult, error) {
	// In sync mode every unit behaves as if its count were leaderCount-1, so
	// that all units land on exactly leaderCount.
	current := state
	var base *int
	if plan.syncMode {
		b := plan.leader.RotationCount - 1
		base = &b
		current.RotationCount = b
	}
	target := targetBackupSlot(current.RotationCount)

	// Single unit left locked by an earlier attempt: compare slot 3 with the
	// target backup slot to find out whether the rotation reached the HSM.
	if plan.singlePartial {
		hashes, _, err := ops.listSlots(cuID)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrMBKRotationIncomplete, err)
		}
		slot3, backup := hashes[MBKSlotActive], hashes[target]
		if slot3 != "" && backup != "" && slot3 == backup {
			// Rotation completed on the HSM but the DB was not updated.
			return nil, ErrMBKRecordSyncRequired
		}
		// Rotation did not complete on the HSM: release the lock, ask for a re-run.
		abortRotation(ctx, ops, logger, cuID)
		return nil, ErrMBKRotationIncomplete
	}

	// An earlier rotation failed and the operator unlocked a retry: the partial
	// state is authoritative, so CMS validation is skipped.
	incompleteRetry := !plan.syncMode && !isImportSuccessfulOrNil(current)
	if incompleteRetry {
		logger.Warn("the previous master key rotation of crypto unit %s did not complete; proceeding with retry", cuID)
	}
	skipValidation := plan.syncMode || incompleteRetry

	// Read before the preflight lock, so a failure here cannot leave the unit locked.
	adminCount, err := ops.authenticatedAdmins(cuID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve authenticated admin count: %w", err)
	}

	// Step 0: preflight. CMS validates the import gate and locks the unit
	// (is_import_successful=FALSE, allow_import=FALSE) before any HSM write.
	if _, err := ops.rotateRecord(ctx, cuID, rotateMBKRequest{SkipValidation: skipValidation, BaseRotationCount: base}); err != nil {
		return nil, err
	}

	// Step 1: import the new key into the target backup slot. Nothing has been
	// written if this fails, so the lock is released.
	if err := ops.importKey(ctx, cuID, keyspec, target, adminCount, true); err != nil {
		abortRotation(ctx, ops, logger, cuID)
		return nil, fmt.Errorf("master key rotation failed: the new master key could not be imported (authenticated-admin-count=%d); the system is unchanged and still holds the old master key, retry the operation: %w", adminCount, err)
	}

	// Step 2: import the same key into the active slot. On failure the HSM is
	// partial (backup slot new, active slot old) and the lock stays.
	if err := ops.importKey(ctx, cuID, keyspec, MBKSlotActive, adminCount, true); err != nil {
		detail := ""
		if hashes, _, listErr := ops.listSlots(cuID); listErr == nil {
			if backupHash, ok := hashes[target]; ok {
				active := "not present"
				if h, ok := hashes[MBKSlotActive]; ok {
					active = h
				}
				detail = fmt.Sprintf(" (backup slot %d holds the new master key hash=%s, active slot: %s)", target, backupHash, active)
			}
		}
		return nil, fmt.Errorf("%w: the new master key was stored but could not be activated%s: %v", ErrMBKRotationIncomplete, detail, err)
	}

	// Step 3: read back the slot hashes.
	hashes, _, err := ops.listSlots(cuID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMBKRotationIncomplete, err)
	}
	newHash, ok := hashes[MBKSlotActive]
	if !ok {
		return nil, fmt.Errorf("%w: slot %d not found after import", ErrMBKRotationIncomplete, MBKSlotActive)
	}

	// Step 4: the active key must match one of the backup slots.
	found := false
	for _, s := range backupSlots {
		if h, exists := hashes[s]; exists && h == newHash {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w: the active master key matches no backup slot", ErrMBKRotationIncomplete)
	}

	// Step 5: commit atomically to the database.
	slotHashes := make(map[string]string, len(hashes))
	for slot, h := range hashes {
		slotHashes[strconv.Itoa(slot)] = h
	}
	resp, err := ops.rotateRecord(ctx, cuID, rotateMBKRequest{
		NewHashedMBK:      newHash,
		SlotHashes:        slotHashes,
		SkipValidation:    skipValidation,
		BaseRotationCount: base,
	})
	if err != nil {
		// With several units the right recovery is to re-run rotate; record-sync
		// is only correct for a single unit.
		if cuCount > 1 {
			return nil, fmt.Errorf("%w: %v", ErrMBKOutOfSync, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrMBKRecordSyncRequired, err)
	}

	return &MBKRotationResult{
		CryptoUnitID:     cuID,
		RotationCount:    resp.RotationCount,
		TargetBackupSlot: resp.TargetBackupSlot,
		NewHashedMBK:     resp.NewHashedMBK,
	}, nil
}

// syncMasterKeyRecord repairs or seeds the CMS record of one crypto unit from
// the HSM, as the CLI 'master-key record-sync' does. cuCount is the number of
// crypto units in the instance: the repair flow only applies to a single unit.
func syncMasterKeyRecord(ctx context.Context, ops mbkOps, cuID string, state CryptoUnitMBKState, cuCount int) (*RecordSyncResult, error) {
	hashes, genDate, err := ops.listSlots(cuID)
	if err != nil {
		return nil, err
	}
	slot3, ok := hashes[MBKSlotActive]
	if !ok {
		return nil, fmt.Errorf("no active master key found in the HSM of crypto unit %s", cuID)
	}

	// Seed flow: hashed_mbk is NULL. rotation_count and the import flags are
	// not touched.
	if state.HashedMBK == nil || *state.HashedMBK == "" {
		if _, ok := hashes[MBKSlotBackup]; !ok {
			return nil, fmt.Errorf("backup master key not found in the HSM of crypto unit %s; the initial master key import may not have completed", cuID)
		}
		resp, err := ops.syncRecord(ctx, cuID, recordSyncRequest{
			Scenario:       recordSyncScenarioSeed,
			SlotHashes:     hashes,
			GenerationDate: genDate,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to seed the master key record in CMS: %w", err)
		}
		return &RecordSyncResult{
			CryptoUnitID: cuID,
			Action:       RecordSyncActionSeeded,
			Message:      fmt.Sprintf("Database seeded. hashed_mk=%s, backup slot=%d. %s", slot3, MBKSlotBackup, resp.Message),
		}, nil
	}

	// Repair flow: a single unit, locked, with the rotation done on the HSM
	// but never recorded.
	if cuCount == 1 && isFreshRotationState(state) {
		target := targetBackupSlot(state.RotationCount)
		backup := hashes[target]
		if slot3 != "" && backup != "" && slot3 == backup {
			resp, err := ops.syncRecord(ctx, cuID, recordSyncRequest{
				Scenario:       recordSyncScenarioRepair,
				SlotHashes:     hashes,
				GenerationDate: genDate,
				RotationCount:  state.RotationCount,
				OldHashedMBK:   *state.HashedMBK,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to repair the master key record in CMS: %w", err)
			}
			return &RecordSyncResult{
				CryptoUnitID:  cuID,
				Action:        RecordSyncActionRepaired,
				RotationCount: resp.RotationCount,
				Message:       fmt.Sprintf("Database repaired. rotation_count=%d, backup_slot=%d, hashed_mk=%s", resp.RotationCount, target, slot3),
			}, nil
		}
		return &RecordSyncResult{
			CryptoUnitID: cuID,
			Action:       RecordSyncActionNoOp,
			Message:      fmt.Sprintf("No repair needed: the previous rotation did not complete for crypto unit %s. Re-run the rotation to retry.", cuID),
		}, nil
	}

	return &RecordSyncResult{
		CryptoUnitID: cuID,
		Action:       RecordSyncActionNoOp,
		Message:      fmt.Sprintf("No action required: the master key record for crypto unit %s is already up to date (hashed_mk=%s).", cuID, *state.HashedMBK),
	}, nil
}

// importMasterKeyAndSeed is the CLI 'master-key import' flow: import into the
// backup slot (8), then the active slot (3), then seed the database record. A
// failed seed is returned wrapping ErrMBKSeedFailed; the HSM import has then
// succeeded and a record-sync repairs the record.
func importMasterKeyAndSeed(ctx context.Context, ops mbkOps, cuID, keyspec string) error {
	adminCount, err := ops.authenticatedAdmins(cuID)
	if err != nil {
		return wrapError(err, fmt.Sprintf("failed to count authenticated admins of crypto unit %s", cuID))
	}
	for _, slot := range []int{MBKSlotBackup, MBKSlotActive} {
		if err := ops.importKey(ctx, cuID, keyspec, slot, adminCount, false); err != nil {
			return wrapError(err, fmt.Sprintf("failed to import Master Key into slot %d of crypto unit %s", slot, cuID))
		}
	}
	if _, err := seedMasterKeyRecord(ctx, ops, cuID); err != nil {
		return fmt.Errorf("crypto unit %s: %w: %v", cuID, ErrMBKSeedFailed, err)
	}
	return nil
}
