# KeyProtect CryptoUnit Go SDK - API

This package provides a simplified, secure Go interface to KeyProtect Dedicated CryptoUnits.

## Overview

This is the **public API** for the KeyProtect Dedicated keyprotect-dedicated Go wrapper. The actual implementation is packaged separately as platform-specific prebuilt artifacts while maintaining ease of use.

> Current packaging contract: the public module remains source-only, while the build pipeline publishes standardized platform archives containing redistributed prebuilt Go archive artifacts and vendor libraries for future integration.

## Installation

### Simple Installation (Recommended)

The easiest way to use this package is via `go get`. The shared libraries are **automatically included** with the module:

```bash
# Install the package (includes embedded shared libraries)
go get github.com/IBM/keyprotect-go-client/dedicated

# Use in your project - NO CGO REQUIRED!
# The libraries are automatically found at runtime
```

**Key Benefits:**

- ✅ **No CGO required** - Pure Go builds for consumers
- ✅ **Fast builds** - Compiles in seconds, not minutes
- ✅ **Easy cross-compilation** - Standard Go tooling works
- ✅ **Automatic library loading** - No manual setup needed

### How It Works

The module includes precompiled shared libraries for all supported platforms in `internal/lib/`:

- `linux-amd64/ibmkmscrypto.so.${VERSION}`
- `darwin-arm64/ibmkmscrypto.${VERSION}.dylib`
- `windows-amd64/ibmkmscrypto.dll`

At runtime, the package automatically finds and loads the correct library for your platform using [purego](https://github.com/ebitengine/purego).

### Advanced: Custom Library Location

If you need to use a custom library version, set the environment variable:

```bash
export KEYPROTECT_LIB_PATH=/path/to/custom/libs
```

## Quick Start

### Using the Go API

```go
package main

import (
    "os"
    "fmt"
    "log"

    "github.com/IBM/go-sdk-core/v5/core"
    keyprotect_dedicated "github.com/IBM/keyprotect-go-client/dedicated"
)

func main() {
  iamAPIKey, apiKeyFound := os.LookupEnv("IBMCLOUD_API_KEY")

 // Create client configuration
 config := &keyprotect_dedicated.KeyProtectCryptoUnitAPIOptions{
  URL:         "https://<instance_id>.api.st.<region>.kms.appdomain.cloud",
  Authenticator: &core.IamAuthenticator{
   ApiKey: iamAPIKey,
   URL:    "https://iam.cloud.ibm.com",
  },
 }

 // Create new client
 client, disconnect, err := keyprotect_dedicated.NewKeyProtectCryptoUnitAPI(config)
 if err != nil {
  log.Fatalf("Failed to create client: %v", err)
 }
 defer disconnect ()

 // Initialize all cryptounits
 rootKeySpec, err := keyprotect_dedicated.NewSignatureKeyRequest(
  "signature.key",
  "",
  "ADMIN",
  false,
 )
 if err != nil {
  log.Fatalf("error creating signature key request: %s", err)
 }

 mbkSpec, err := keyprotect_dedicated.NewMasterKeyPartsSpec(
  2,
  "IFHLSM",
  []string{
   "mbk-1.key#abcd12",
   "mbk-2.key#abcd12",
  },
  false,
 )
 if err != nil {
  log.Fatalf("error creating NewMasterKeyPartsSpec  request: %s", err)
 }

 err = client.InitializeCryptoUnits(context.Background(), rootKeySpec, nil, nil, mbkSpec, instanceID)
 if err != nil {
  log.Fatalf("Failed to initialize cryptounits: %v", err)
 }

 // Get crypto units
 fmt.Println("Listing crypto units...")
 units, _, err := client.ListCryptoUnits(defaultSettings)
 if err != nil {
  log.Fatalf("Failed to list crypto units: %v", err)
 }

 fmt.Printf("Found %d crypto units:\n", len(units.CryptoUnits))

 for k, v := range units.CryptoUnits {
  fmt.Printf("index %d crypto units %v:\n", k, v)
 }

 // To connect to the first crypto unit and not initialize
 cryptoUnitID := units.CryptoUnits[0].ID

 err = client.CreateCryptoUnitSession(
  Username: "<username>", // username
  KeyFile: "<>", // key file path
  CryptoUnitID: cryptoUnitID, // crypto unit ID
  Port: 443,          // port (0 = default)
 )
 if err != nil {
  log.Fatalf("Failed to connect to crypto unit: %v", err)
 }
```

## API Reference

### Methods (on KeyProtectCryptoUnitAPI)

#### Factory Functions (Constructors)

- NewSignatureKeyRequest(filepath, passphrase, owner string, exists bool) (*SignatureKeyRequest, error)
- NewMasterKeyPartsSpec(K int, keyName string, keysharefiles []string, exists bool) (*MasterKeyPartsSpec, error)
- NewKeyProtectCryptoUnitAPIOptions(url string) (*KeyProtectCryptoUnitAPIOptions, error)
- NewKeyProtectCryptoUnitAPI(options *KeyProtectCryptoUnitAPIOptions) (service*KeyProtectCryptoUnitAPI, disconnect func(), err error)
- NewKeyProtectCryptoUnitAPIUsingExternalConfig(options *KeyProtectCryptoUnitAPIOptions) (keyProtectCryptoUnitAPI*KeyProtectCryptoUnitAPI, disconnect func(), err error)

#### Configuration & Setup

- SetDefaultHeaders(headers http.Header) - Sets default HTTP headers
- GetServiceURL() string - Gets the service URL
- SetLogger(logger core.Logger) - Sets the logger
- GetLogger() core.Logger - Gets the logger

#### Session Management

- CreateCryptoUnitSession(loginSpec *LoginSpec) error - Creates a session with a crypto unit
- GetConnectedCryptoUnits() []string - Gets list of connected crypto units
- Disconnect(cryptoUnitID string) error - Disconnects from a specific crypto unit
- DisconnectAll() - Disconnects from all crypto units
- GetSessionInfo(cryptoUnitID string) (*SessionInfo, error) - Gets session information
- GetAuthState(cryptoUnitID string) (uint32, error) - Gets authentication state

#### Crypto Unit Operations

- ListCryptoUnits() (cryptounits CryptoUnits, response *core.DetailedResponse, err error) - Lists crypto units
- ListCryptoUnitsWithContext(ctx context.Context) (crytounits CryptoUnits, response *core.DetailedResponse, err error) - Lists crypto units with context
- ClaimCryptoUnit(cryptoUnitID string, filepath string) error - Claims a crypto unit
- ClaimCryptoUnitWithContext(ctx context.Context, cryptoUnitID string, filePath string) error - Claims crypto unit with context
- ZeroizeCryptoUnit(cryptoUnitID string) error - Zeroizes a crypto unit
- ZeroizeCryptoUnitWithContext(ctx context.Context, cryptoUnitID string) error - Zeroizes crypto unit with context
- InitializeCryptoUnits(ctx context.Context, skr *SignatureKeyRequest, adminReq []*AdditionalAdminRequest, thresholdReq *ThresholdRequest, mbkspec *MasterKeyPartsSpec, instanceID string) error - Initializes crypto units (adminReq and thresholdReq are optional, pass nil to skip)
- SetThreshold(cryptoUnitID string, signatureThreshold, revocationThreshold int) error - Sets the signature and revocation thresholds of a crypto unit
- SetThresholdWithContext(ctx context.Context, cryptoUnitID string, signatureThreshold, revocationThreshold int) error - Sets thresholds with context
- GetThreshold(cryptoUnitID string) ([]CryptoUnitThreshold, error) - Gets the thresholds of all crypto units, or of one when cryptoUnitID is set
- GetThresholdWithContext(ctx context.Context, cryptoUnitID string) ([]CryptoUnitThreshold, error) - Gets thresholds with context

##### Setting thresholds

`SetThreshold` configures how many admin signatures are required to authorize commands (signature threshold) and to revoke admins (revocation threshold).

- Both values must be between `MinThreshold` (1) and `MaxThreshold` (5).
- The crypto unit must have at least `max(signatureThreshold, revocationThreshold)` admin users.
- The crypto unit must be in the `claimed` state, and you must already be connected to it with an admin user.
- The threshold can only be set once. To change it, the crypto unit must be in the `claimed` state again.
- The HSM restarts after the configuration is applied, so reconnect before running further operations on that crypto unit.

```go
err = client.SetThreshold(cryptoUnitID, 2, 2)
if err != nil {
    log.Fatalf("Failed to set threshold: %v", err)
}
```

`GetThreshold` reads the thresholds from the management API (the same list call as `ListCryptoUnits`), so it does not need a crypto unit session. A value of `0` means the threshold has not been configured on that unit; `Configured()` reports whether both values are set.

```go
// All crypto units of the instance
thresholds, err := client.GetThreshold("")
if err != nil {
    log.Fatalf("Failed to get thresholds: %v", err)
}
for _, t := range thresholds {
    fmt.Printf("%s state=%s signature=%d revocation=%d configured=%t\n",
        t.CryptoUnitID, t.State, t.SignatureThreshold, t.RevocationThreshold, t.Configured())
}

// A single crypto unit
thresholds, err = client.GetThreshold(cryptoUnitID)
```

#### User Management

- ListUsers(cryptoUnitID string) ([]UserInfo, error) - Lists users on a crypto unit
- AddUser(cryptoUnitID string, req *AddUserRequest) error - Adds a user
- AddUserWithContext(ctx context.Context, cryptoUnitID string, req *AddUserRequest) error - Adds user with context
- AddKMSUser(ctx context.Context, cryptoUnitID string) ([]UserInfo, error) - Adds a KMS user
- DeleteUser(cryptoUnitID string, username string) error - Deletes a user
- DeleteUserWithContext(ctx context.Context, cryptoUnitID string, username string) error - Deletes user with context
- Key Management
- GenerateSignatureKey(instanceID string, req *SignatureKeyRequest) error - Generates a signature key
- ListMasterKeys(cryptoUnitID string) ([]MasterKeyInfo, error) - Lists master keys
- ListMasterKeysWithContext(ctx context.Context, cryptoUnitID string) ([]MasterKeyInfo, error) - Lists master keys with context
- GenerateMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) - Generates a master key
- GenerateMasterKeyWithContext(ctx context.Context, cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) (string, error) - Generates master key with context
- ImportMasterKey(cryptoUnitID string, mbkSpec *MasterKeyPartsSpec) error - Imports a master key (slots 8 and 3, then seeds the record)
- ImportMasterKeyWithContext(ctx context.Context, cryptoUnitID string, request *MasterKeyPartsSpec) error - Imports master key with context
- ImportMasterKeyToCryptoUnits(ctx context.Context, cryptoUnitIDs []string, request *MasterKeyPartsSpec) error - Imports master key to multiple crypto units

##### Import behavior

Import follows the `master-key import` CLI command. With the default slot (`SlotNo` 0 or 3) the key is imported
into the backup slot 8 and then the active slot 3. The number of authenticated admins of the session is sent to the
management service, so the crypto unit must be connected with enough admins to satisfy the signature threshold
(see `CreateCryptoUnitSession` and `LoginSpec.AdditionalAuths`). Afterwards the master key record of the crypto unit
is seeded in the database.

If only the seeding fails, the HSM import has succeeded and the error wraps `ErrMBKSeedFailed`. Check for it with
`errors.Is` and run `SyncMasterKeyRecord`. `ImportMasterKeyToCryptoUnits` logs this as a warning and does not fail.
Any other `SlotNo` imports into that single slot only and does not seed.

#### Master Key Rotation

- GetMasterKeyState(cryptoUnitID string) (*CryptoUnitMBKState, error) - Reads the master key state held by the management service (hash, rotation count, import flags). Needs no session, so it suits a Terraform read.
- GetMasterKeyStateWithContext(ctx context.Context, cryptoUnitID string) (*CryptoUnitMBKState, error) - Same, with context
- RotateMasterKey(cryptoUnitID string, spec *MasterKeyPartsSpec) (*MBKRotationResult, error) - Rotates the master key of one crypto unit
- RotateMasterKeyWithContext(ctx context.Context, cryptoUnitID string, spec *MasterKeyPartsSpec) (*MBKRotationResult, error) - Same, with context
- RotateMasterKeyOnCryptoUnits(ctx context.Context, cryptoUnitIDs []string, spec *MasterKeyPartsSpec) ([]MBKRotationResult, error) - Rotates several crypto units of an instance
- SyncMasterKeyRecord(cryptoUnitID string) (*RecordSyncResult, error) - Seeds or repairs the management service record from the HSM
- SyncMasterKeyRecordWithContext(ctx context.Context, cryptoUnitID string) (*RecordSyncResult, error) - Same, with context
- SyncMasterKeyRecordOnCryptoUnits(ctx context.Context, cryptoUnitIDs []string) ([]RecordSyncResult, error) - Same for several crypto units

Rotation follows the `master-key rotate` CLI command: the new key shares must already exist
(`GenerateMasterKey`), and the client must be connected to every crypto unit with enough admins to satisfy the
signature threshold. The flow is a preflight check with the management service, an import into the next backup slot
(cycling through 9, 10, 11, 12, 8), an import into slot 3, a read back and verification, and a commit. If the
rotation counts of the units differ, all units are rotated onto the highest count. Like the CLI, rotation stops at
the first failing unit and returns the results of the units rotated before it.

```go
spec := &dedicated.MasterKeyPartsSpec{KeyShareFiles: []string{"mk-share1.key#pass1", "mk-share2.key#pass2"}}

state, err := client.GetMasterKeyState(cryptoUnitID)
// state.RotationCount, state.HashedMBK, ...

results, err := client.RotateMasterKeyOnCryptoUnits(ctx, cryptoUnitIDs, spec)
switch {
case errors.Is(err, dedicated.ErrMBKRecordSyncRequired):
    // HSM rotated, database not updated (single crypto unit): call SyncMasterKeyRecord
    _, err = client.SyncMasterKeyRecord(cryptoUnitIDs[0])
case errors.Is(err, dedicated.ErrMBKOutOfSync), errors.Is(err, dedicated.ErrMBKRotationIncomplete):
    // run the rotation again, it recovers or syncs the crypto units
}
```

| Error | Meaning | Recovery |
| --- | --- | --- |
| `ErrMBKRotationIncomplete` | The HSM state is partial or could not be confirmed | Run the rotation again |
| `ErrMBKRecordSyncRequired` | The rotation finished on the HSM but the database was not updated (single crypto unit) | `SyncMasterKeyRecord` |
| `ErrMBKOutOfSync` | The database commit failed with several crypto units, so their rotation counts differ | Run the rotation again |
| `ErrMBKSeedFailed` | Import succeeded but the database record was not seeded | `SyncMasterKeyRecord` |

Smart card admins are not supported by this client; use key file based admins.

#### Audit

- GetAuditLog(cryptoUnitID string) (*AuditLog, error) - Gets audit log

## Platform Support

- Linux (amd64)
- macOS (Apple Silicon)
- Windows (amd64)

## Requirements

### For Consumers (Using the Package)

- **Go 1.21 or later**
- **No CGO required** - `CGO_ENABLED=0` works fine!
- **No C compiler needed** - Pure Go builds

### For Maintainers (Building the Package)

- Go 1.21 or later
- CGO enabled (`CGO_ENABLED=1`)
- GCC or compatible C compiler
- Platform-specific toolchains for cross-compilation

### Runtime Dependencies

- Shared libraries are self-contained (OpenSSL 1.1 statically linked)
- No external dependencies required

## Support

For support, please contact:

- Email: <support@ibm.com>
- Documentation: <https://cloud.ibm.com/docs/key-protect>

## License

This software is provided under the IBM license agreement. Refer to the LICENSE file for terms and conditions.

### v1.0.0 (2026-04-10)

- Initial release
- Support for initializing KeyProtect Dedicated CryptoUnits
- Pre-compiled binaries for all major platforms
