package dedicated

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func quietLogger() core.Logger {
	l := log.New(io.Discard, "", 0)
	return core.NewLogger(core.LevelError, l, l)
}

func boolPtr(b bool) *bool { return &b }
func strPtr(s string) *string {
	return &s
}

// fakeOps is an in-memory mbkOps that records every call in order.
type fakeOps struct {
	calls []string

	// listResults are returned by successive listSlots calls; the last one repeats.
	listResults []map[int]string
	listCalls   int
	listErr     error

	adminCount int
	adminErr   error

	importErr map[int]error // slot -> error
	imports   []importCall

	rotateReqs []rotateMBKRequest
	rotateErrs []error // per rotateRecord call; nil entries succeed
	rotateResp rotateMBKResponse

	syncReqs []recordSyncRequest
	syncErr  error
}

type importCall struct {
	slot, admins int
	isRotate     bool
}

func (f *fakeOps) rotateRecord(_ context.Context, _ string, req rotateMBKRequest) (*rotateMBKResponse, error) {
	f.calls = append(f.calls, "rotateRecord")
	f.rotateReqs = append(f.rotateReqs, req)
	if n := len(f.rotateReqs) - 1; n < len(f.rotateErrs) && f.rotateErrs[n] != nil {
		return nil, f.rotateErrs[n]
	}
	resp := f.rotateResp
	return &resp, nil
}

func (f *fakeOps) syncRecord(_ context.Context, _ string, req recordSyncRequest) (*recordSyncResponse, error) {
	f.calls = append(f.calls, "syncRecord")
	f.syncReqs = append(f.syncReqs, req)
	if f.syncErr != nil {
		return nil, f.syncErr
	}
	return &recordSyncResponse{RotationCount: req.RotationCount, Message: "ok"}, nil
}

func (f *fakeOps) importKey(_ context.Context, _, _ string, slot, admins int, isRotate bool) error {
	f.calls = append(f.calls, fmt.Sprintf("import%d", slot))
	f.imports = append(f.imports, importCall{slot, admins, isRotate})
	return f.importErr[slot]
}

func (f *fakeOps) listSlots(_ string) (map[int]string, time.Time, error) {
	f.calls = append(f.calls, "listSlots")
	if f.listErr != nil {
		return nil, time.Time{}, f.listErr
	}
	if len(f.listResults) == 0 {
		return nil, time.Time{}, errors.New("no slots configured")
	}
	i := f.listCalls
	if i >= len(f.listResults) {
		i = len(f.listResults) - 1
	}
	f.listCalls++
	return f.listResults[i], time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), nil
}

func (f *fakeOps) authenticatedAdmins(_ string) (int, error) {
	return f.adminCount, f.adminErr
}

// ************ pure helpers ************

func TestTargetBackupSlot(t *testing.T) {
	want := []int{9, 10, 11, 12, 8, 9, 10}
	for count, slot := range want {
		assert.Equal(t, slot, targetBackupSlot(count), "rotation count %d", count)
	}
	assert.Equal(t, 9, targetBackupSlot(-1))
}

func TestParseSlotHashes(t *testing.T) {
	raw := `slot name len algo type k date time kcv
-----------------------------------------
3 MBK 32 AES SECRET 1 2025/03/04 05:06:07 AAAA1111
8 MBK 32 AES SECRET 1 2025/03/04 05:06:07 AAAA1111
10 MBK 32 AES SECRET 1 2024/01/01 00:00:00 BBBB2222
not a row
`
	hashes, date, err := parseSlotHashes(raw)
	require.NoError(t, err)
	assert.Equal(t, map[int]string{3: "AAAA1111", 8: "AAAA1111", 10: "BBBB2222"}, hashes)
	assert.Equal(t, time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC), date)

	_, _, err = parseSlotHashes("slot header only\n")
	assert.Error(t, err)

	_, _, err = parseSlotHashes("3 MBK 32 AES SECRET 1 not-a-date 05:06:07 AAAA1111")
	assert.Error(t, err)
}

func TestCountAuthenticatedAdmins(t *testing.T) {
	users := []UserInfo{
		{Username: "ADMIN1", Permissions: AdminPermission},
		{Username: "ADMIN2", Permissions: AdminPermission},
		{Username: "KMS", Permissions: 0x1},
		{Username: "ADMIN3", Permissions: AdminPermission},
	}
	assert.Equal(t, 2, countAuthenticatedAdmins(users, "ADMIN1, ADMIN3"))
	assert.Equal(t, 1, countAuthenticatedAdmins(users, "ADMIN2,KMS"))
	assert.Equal(t, 0, countAuthenticatedAdmins(users, ""))
}

func TestPlanRotation(t *testing.T) {
	locked := CryptoUnitMBKState{RotationCount: 1, AllowImport: boolPtr(false), IsImportSuccessful: boolPtr(false)}

	t.Run("equal counts", func(t *testing.T) {
		p := planRotation([]string{"a", "b"}, map[string]CryptoUnitMBKState{"a": {RotationCount: 2}, "b": {RotationCount: 2}})
		assert.False(t, p.syncMode)
		assert.False(t, p.singlePartial)
	})
	t.Run("differing counts pick the highest as leader", func(t *testing.T) {
		p := planRotation([]string{"a", "b", "c"}, map[string]CryptoUnitMBKState{
			"a": {RotationCount: 1}, "b": {RotationCount: 3}, "c": {RotationCount: 2},
		})
		assert.True(t, p.syncMode)
		assert.Equal(t, 3, p.leader.RotationCount)
	})
	t.Run("single locked unit", func(t *testing.T) {
		p := planRotation([]string{"a"}, map[string]CryptoUnitMBKState{"a": locked})
		assert.True(t, p.singlePartial)
		assert.False(t, p.syncMode)
	})
	t.Run("locked unit among several is not single-partial", func(t *testing.T) {
		p := planRotation([]string{"a", "b"}, map[string]CryptoUnitMBKState{"a": locked, "b": locked})
		assert.False(t, p.singlePartial)
	})
	t.Run("no units", func(t *testing.T) {
		assert.Equal(t, rotationPlan{}, planRotation(nil, nil))
	})
}

func TestValidateRotateSpec(t *testing.T) {
	_, err := validateRotateSpec(nil)
	assert.Error(t, err)
	_, err = validateRotateSpec(&MasterKeyPartsSpec{})
	assert.Error(t, err)
	_, err = validateRotateSpec(&MasterKeyPartsSpec{KeyShareFiles: []string{"/does/not/exist.key#pw"}})
	assert.Error(t, err)

	f := t.TempDir() + "/a.key"
	require.NoError(t, os.WriteFile(f, []byte("x"), 0o600))
	spec, err := validateRotateSpec(&MasterKeyPartsSpec{KeyShareFiles: []string{f + "#pw", f + "#pw2"}})
	require.NoError(t, err)
	assert.Equal(t, f+"#pw,"+f+"#pw2", spec)
}

// ************ rotate flow ************

func slots(active, backup8 string, extra map[int]string) map[int]string {
	m := map[int]string{3: active, 8: backup8}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func newRotateOps() *fakeOps {
	return &fakeOps{
		adminCount: 2,
		rotateResp: rotateMBKResponse{RotationCount: 1, TargetBackupSlot: 9, NewHashedMBK: "NEW"},
		listResults: []map[int]string{
			slots("NEW", "OLD", map[int]string{9: "NEW"}),
		},
	}
}

func rotate(ops *fakeOps, state CryptoUnitMBKState, plan rotationPlan, cuCount int) (*MBKRotationResult, error) {
	return rotateMasterKey(context.Background(), ops, quietLogger(), "cu1", "k.key#pw", state, plan, cuCount)
}

func TestRotateMasterKey_Success(t *testing.T) {
	ops := newRotateOps()
	res, err := rotate(ops, CryptoUnitMBKState{RotationCount: 0}, rotationPlan{}, 1)
	require.NoError(t, err)
	assert.Equal(t, &MBKRotationResult{CryptoUnitID: "cu1", RotationCount: 1, TargetBackupSlot: 9, NewHashedMBK: "NEW"}, res)

	// preflight, backup slot, active slot, read back, commit
	assert.Equal(t, []string{"rotateRecord", "import9", "import3", "listSlots", "rotateRecord"}, ops.calls)
	for _, c := range ops.imports {
		assert.Equal(t, 2, c.admins)
		assert.True(t, c.isRotate)
	}
	require.Len(t, ops.rotateReqs, 2)
	assert.False(t, ops.rotateReqs[0].SkipValidation)
	assert.Equal(t, "NEW", ops.rotateReqs[1].NewHashedMBK)
	assert.Equal(t, "NEW", ops.rotateReqs[1].SlotHashes["3"])
	assert.Equal(t, "OLD", ops.rotateReqs[1].SlotHashes["8"])
}

func TestRotateMasterKey_SyncMode(t *testing.T) {
	ops := newRotateOps()
	// leader has count 5, so every unit behaves as count 4 and lands on slot 8.
	plan := rotationPlan{syncMode: true, leader: CryptoUnitMBKState{RotationCount: 5}}
	_, err := rotate(ops, CryptoUnitMBKState{RotationCount: 2}, plan, 2)
	require.NoError(t, err)

	assert.Equal(t, 8, ops.imports[0].slot)
	for _, req := range ops.rotateReqs {
		assert.True(t, req.SkipValidation)
		require.NotNil(t, req.BaseRotationCount)
		assert.Equal(t, 4, *req.BaseRotationCount)
	}
}

func TestRotateMasterKey_IncompleteRetrySkipsValidation(t *testing.T) {
	ops := newRotateOps()
	_, err := rotate(ops, CryptoUnitMBKState{RotationCount: 1, IsImportSuccessful: boolPtr(false), AllowImport: boolPtr(true)}, rotationPlan{}, 2)
	require.NoError(t, err)
	assert.True(t, ops.rotateReqs[0].SkipValidation)
	assert.Nil(t, ops.rotateReqs[0].BaseRotationCount)
}

func TestRotateMasterKey_SinglePartial(t *testing.T) {
	locked := CryptoUnitMBKState{RotationCount: 0, AllowImport: boolPtr(false), IsImportSuccessful: boolPtr(false)}
	plan := rotationPlan{singlePartial: true}

	t.Run("completed on HSM needs record-sync", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("NEW", "OLD", map[int]string{9: "NEW"})}}
		_, err := rotate(ops, locked, plan, 1)
		assert.ErrorIs(t, err, ErrMBKRecordSyncRequired)
		assert.Empty(t, ops.imports)
		assert.Empty(t, ops.rotateReqs, "the lock must stay so record-sync can repair")
	})
	t.Run("not completed releases the lock", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("OLD", "OLD", map[int]string{9: "NEW"})}}
		_, err := rotate(ops, locked, plan, 1)
		assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
		require.Len(t, ops.rotateReqs, 1)
		assert.True(t, ops.rotateReqs[0].Aborted)
		assert.Empty(t, ops.imports)
	})
	t.Run("HSM read failure", func(t *testing.T) {
		ops := &fakeOps{listErr: errors.New("boom")}
		_, err := rotate(ops, locked, plan, 1)
		assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
	})
}

func TestRotateMasterKey_AdminCountFailureLeavesNoLock(t *testing.T) {
	ops := newRotateOps()
	ops.adminErr = errors.New("no session")
	_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
	require.Error(t, err)
	assert.Empty(t, ops.calls, "nothing may be sent to CMS or the HSM")
}

func TestRotateMasterKey_PreflightRejected(t *testing.T) {
	ops := newRotateOps()
	ops.rotateErrs = []error{errors.New("rotation not allowed yet")}
	_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
	require.Error(t, err)
	assert.Equal(t, []string{"rotateRecord"}, ops.calls)
}

func TestRotateMasterKey_BackupImportFailureAborts(t *testing.T) {
	ops := newRotateOps()
	ops.importErr = map[int]error{9: errors.New("hsm error")}
	_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrMBKRotationIncomplete)
	assert.Equal(t, []string{"rotateRecord", "import9", "rotateRecord"}, ops.calls)
	assert.True(t, ops.rotateReqs[1].Aborted)
}

func TestRotateMasterKey_ActiveImportFailureIsPartial(t *testing.T) {
	ops := newRotateOps()
	ops.importErr = map[int]error{3: errors.New("hsm error")}
	_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
	assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
	assert.Contains(t, err.Error(), "backup slot 9")
	for _, r := range ops.rotateReqs {
		assert.False(t, r.Aborted, "the lock must stay after a partial HSM write")
	}
}

func TestRotateMasterKey_VerificationFailures(t *testing.T) {
	t.Run("active slot missing", func(t *testing.T) {
		ops := newRotateOps()
		ops.listResults = []map[int]string{{8: "OLD"}}
		_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
		assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
	})
	t.Run("active slot matches no backup", func(t *testing.T) {
		ops := newRotateOps()
		ops.listResults = []map[int]string{{3: "NEW", 8: "OLD"}}
		_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
		assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
	})
	t.Run("read back fails", func(t *testing.T) {
		ops := newRotateOps()
		ops.listErr = errors.New("boom")
		_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
		assert.ErrorIs(t, err, ErrMBKRotationIncomplete)
	})
}

func TestRotateMasterKey_CommitFailure(t *testing.T) {
	t.Run("single unit asks for record-sync", func(t *testing.T) {
		ops := newRotateOps()
		ops.rotateErrs = []error{nil, errors.New("cms down")}
		_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 1)
		assert.ErrorIs(t, err, ErrMBKRecordSyncRequired)
		assert.NotErrorIs(t, err, ErrMBKOutOfSync)
	})
	t.Run("several units ask for a re-run", func(t *testing.T) {
		ops := newRotateOps()
		ops.rotateErrs = []error{nil, errors.New("cms down")}
		_, err := rotate(ops, CryptoUnitMBKState{}, rotationPlan{}, 2)
		assert.ErrorIs(t, err, ErrMBKOutOfSync)
		assert.NotErrorIs(t, err, ErrMBKRecordSyncRequired)
	})
}

// ************ record-sync flow ************

func syncRecordFor(ops *fakeOps, state CryptoUnitMBKState, cuCount int) (*RecordSyncResult, error) {
	return syncMasterKeyRecord(context.Background(), ops, "cu1", state, cuCount)
}

func TestSyncMasterKeyRecord_Seed(t *testing.T) {
	ops := &fakeOps{listResults: []map[int]string{slots("AAA", "AAA", nil)}}
	res, err := syncRecordFor(ops, CryptoUnitMBKState{}, 2)
	require.NoError(t, err)
	assert.Equal(t, RecordSyncActionSeeded, res.Action)
	require.Len(t, ops.syncReqs, 1)
	assert.Equal(t, recordSyncScenarioSeed, ops.syncReqs[0].Scenario)
	assert.Equal(t, "AAA", ops.syncReqs[0].SlotHashes[3])

	// an empty hash string counts as not seeded
	ops = &fakeOps{listResults: []map[int]string{slots("AAA", "AAA", nil)}}
	res, err = syncRecordFor(ops, CryptoUnitMBKState{HashedMBK: strPtr("")}, 1)
	require.NoError(t, err)
	assert.Equal(t, RecordSyncActionSeeded, res.Action)
}

func TestSyncMasterKeyRecord_SeedErrors(t *testing.T) {
	ops := &fakeOps{listResults: []map[int]string{{8: "AAA"}}}
	_, err := syncRecordFor(ops, CryptoUnitMBKState{}, 1)
	assert.Error(t, err, "no active key")

	ops = &fakeOps{listResults: []map[int]string{{3: "AAA"}}}
	_, err = syncRecordFor(ops, CryptoUnitMBKState{}, 1)
	assert.Error(t, err, "no backup key")

	ops = &fakeOps{listResults: []map[int]string{slots("AAA", "AAA", nil)}, syncErr: errors.New("cms down")}
	_, err = syncRecordFor(ops, CryptoUnitMBKState{}, 1)
	assert.Error(t, err)

	ops = &fakeOps{listErr: errors.New("boom")}
	_, err = syncRecordFor(ops, CryptoUnitMBKState{}, 1)
	assert.Error(t, err)
}

func TestSyncMasterKeyRecord_Repair(t *testing.T) {
	locked := CryptoUnitMBKState{
		HashedMBK: strPtr("OLD"), RotationCount: 0,
		AllowImport: boolPtr(false), IsImportSuccessful: boolPtr(false),
	}

	t.Run("rotation reached the HSM", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("NEW", "OLD", map[int]string{9: "NEW"})}}
		res, err := syncRecordFor(ops, locked, 1)
		require.NoError(t, err)
		assert.Equal(t, RecordSyncActionRepaired, res.Action)
		require.Len(t, ops.syncReqs, 1)
		assert.Equal(t, recordSyncScenarioRepair, ops.syncReqs[0].Scenario)
		assert.Equal(t, 0, ops.syncReqs[0].RotationCount)
		assert.Equal(t, "OLD", ops.syncReqs[0].OldHashedMBK)
	})
	t.Run("rotation did not reach the HSM", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("OLD", "OLD", map[int]string{9: "OTHER"})}}
		res, err := syncRecordFor(ops, locked, 1)
		require.NoError(t, err)
		assert.Equal(t, RecordSyncActionNoOp, res.Action)
		assert.Empty(t, ops.syncReqs)
	})
	t.Run("repair failure", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("NEW", "OLD", map[int]string{9: "NEW"})}, syncErr: errors.New("cms down")}
		_, err := syncRecordFor(ops, locked, 1)
		assert.Error(t, err)
	})
	t.Run("repair is only for a single unit", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("NEW", "OLD", map[int]string{9: "NEW"})}}
		res, err := syncRecordFor(ops, locked, 2)
		require.NoError(t, err)
		assert.Equal(t, RecordSyncActionNoOp, res.Action)
		assert.Empty(t, ops.syncReqs)
	})
}

func TestSyncMasterKeyRecord_NoOp(t *testing.T) {
	ops := &fakeOps{listResults: []map[int]string{slots("AAA", "AAA", nil)}}
	res, err := syncRecordFor(ops, CryptoUnitMBKState{HashedMBK: strPtr("AAA"), AllowImport: boolPtr(true), IsImportSuccessful: boolPtr(true)}, 1)
	require.NoError(t, err)
	assert.Equal(t, RecordSyncActionNoOp, res.Action)
	assert.Empty(t, ops.syncReqs)
}

// ************ import flow ************

func TestImportMasterKeyAndSeed(t *testing.T) {
	ctx := context.Background()

	t.Run("slot 8 then slot 3 then seed", func(t *testing.T) {
		ops := &fakeOps{adminCount: 3, listResults: []map[int]string{slots("AAA", "AAA", nil)}}
		require.NoError(t, importMasterKeyAndSeed(ctx, ops, "cu1", "k.key#pw"))
		assert.Equal(t, []string{"import8", "import3", "listSlots", "syncRecord"}, ops.calls)
		for _, c := range ops.imports {
			assert.Equal(t, 3, c.admins)
			assert.False(t, c.isRotate)
		}
		assert.Equal(t, recordSyncScenarioSeed, ops.syncReqs[0].Scenario)
	})
	t.Run("slot 8 failure stops before slot 3", func(t *testing.T) {
		ops := &fakeOps{importErr: map[int]error{8: errors.New("hsm error")}}
		err := importMasterKeyAndSeed(ctx, ops, "cu1", "k")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrMBKSeedFailed)
		assert.Equal(t, []string{"import8"}, ops.calls)
	})
	t.Run("slot 3 failure is not a seed warning", func(t *testing.T) {
		ops := &fakeOps{importErr: map[int]error{3: errors.New("hsm error")}}
		err := importMasterKeyAndSeed(ctx, ops, "cu1", "k")
		require.Error(t, err)
		assert.NotErrorIs(t, err, ErrMBKSeedFailed)
	})
	t.Run("seed failure is a warning", func(t *testing.T) {
		ops := &fakeOps{listResults: []map[int]string{slots("AAA", "AAA", nil)}, syncErr: errors.New("cms down")}
		err := importMasterKeyAndSeed(ctx, ops, "cu1", "k")
		assert.ErrorIs(t, err, ErrMBKSeedFailed)

		ops = &fakeOps{listErr: errors.New("boom")}
		err = importMasterKeyAndSeed(ctx, ops, "cu1", "k")
		assert.ErrorIs(t, err, ErrMBKSeedFailed)
		assert.Equal(t, []string{"import8", "import3", "listSlots"}, ops.calls)
	})
	t.Run("admin count failure imports nothing", func(t *testing.T) {
		ops := &fakeOps{adminErr: errors.New("no session")}
		require.Error(t, importMasterKeyAndSeed(ctx, ops, "cu1", "k"))
		assert.Empty(t, ops.imports)
	})
}

// ************ REST helper ************

func newTestAPI(t *testing.T, handler http.HandlerFunc) *KeyProtectCryptoUnitAPI {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	svc, err := core.NewBaseService(&core.ServiceOptions{URL: srv.URL, Authenticator: &core.NoAuthAuthenticator{}})
	require.NoError(t, err)
	return &KeyProtectCryptoUnitAPI{Service: svc, instanceID: "inst-1", logger: quietLogger()}
}

func TestGetMasterKeyState(t *testing.T) {
	api := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/v1/crypto_units/cu-1/master_key", r.URL.Path)
		assert.Equal(t, "cu-1", r.Header.Get("Crypto-Unit-ID"))
		assert.Equal(t, "inst-1", r.Header.Get("Instance-ID"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hashed_MK":"ABC","rotation_count":3,"allow_import":false,"is_import_successful":true}`))
	})
	state, err := api.GetMasterKeyState("cu-1")
	require.NoError(t, err)
	require.NotNil(t, state.HashedMBK)
	assert.Equal(t, "ABC", *state.HashedMBK)
	assert.Equal(t, 3, state.RotationCount)
	require.NotNil(t, state.AllowImport)
	assert.False(t, *state.AllowImport)

	_, err = api.GetMasterKeyState("")
	assert.Error(t, err)
}

func TestGetMasterKeyState_NullHash(t *testing.T) {
	api := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hashed_MK":null,"rotation_count":0}`))
	})
	state, err := api.GetMasterKeyState("cu-1")
	require.NoError(t, err)
	assert.Nil(t, state.HashedMBK)
}

func TestGetMasterKeyState_ServerError(t *testing.T) {
	api := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"not found"}`))
	})
	_, err := api.GetMasterKeyState("cu-1")
	assert.Error(t, err)
}

func TestRotateAndSyncRecordRequests(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	api := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		gotPath = r.URL.Path
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"rotationCount":4,"targetBackupSlot":8,"newHashedMK":"H","message":"done"}`))
	})

	base := 2
	resp, err := api.rotateRecord(context.Background(), "cu-1", rotateMBKRequest{
		NewHashedMBK: "H", SlotHashes: map[string]string{"3": "H"}, SkipValidation: true, BaseRotationCount: &base,
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/crypto_units/cu-1/master_key/rotate", gotPath)
	assert.Equal(t, "H", gotBody["newHashedMK"])
	assert.Equal(t, true, gotBody["skipValidation"])
	assert.EqualValues(t, 2, gotBody["baseRotationCount"])
	assert.NotContains(t, gotBody, "aborted")
	assert.Equal(t, rotateMBKResponse{RotationCount: 4, TargetBackupSlot: 8, NewHashedMBK: "H"}, *resp)

	_, err = api.rotateRecord(context.Background(), "cu-1", rotateMBKRequest{Aborted: true})
	require.NoError(t, err)
	assert.Equal(t, true, gotBody["aborted"])
	assert.NotContains(t, gotBody, "baseRotationCount")

	sync, err := api.syncRecord(context.Background(), "cu-1", recordSyncRequest{
		Scenario: recordSyncScenarioRepair, SlotHashes: map[int]string{3: "H"},
		GenerationDate: time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC), RotationCount: 4, OldHashedMBK: "O",
	})
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/crypto_units/cu-1/master_key/record/sync", gotPath)
	assert.EqualValues(t, 1, gotBody["scenario"])
	assert.Equal(t, map[string]any{"3": "H"}, gotBody["slotHashes"])
	assert.Equal(t, "O", gotBody["oldHashedMBK"])
	assert.Equal(t, "done", sync.Message)
}

func TestCopyHeadersDoesNotMutateInput(t *testing.T) {
	in := map[string]string{"A": "1"}
	out := copyHeaders(in)
	out["B"] = "2"
	assert.NotContains(t, in, "B")
	assert.Equal(t, "1", out["A"])
}

func TestRotateRecord_EmptyBodySucceeds(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusNoContent} {
		api := newTestAPI(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
		})
		resp, err := api.rotateRecord(context.Background(), "cu-1", rotateMBKRequest{})
		require.NoError(t, err, "status %d", status)
		assert.Equal(t, rotateMBKResponse{}, *resp)
	}
}
