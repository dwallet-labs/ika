### How to upgrade the 2pc-mpc Move module

### Step 1: Update the Move dependencies to use the already deployed dependencies
Open `contracts/ika_dwallet_2pc_mpc/Move.toml`, and add an entry to the `addresses` entry:
```
ika = "<IKA_PACKAGE_ID>"
```
Replace the ika package ID with the one from the ika_config.json file.
In the `contracts/ika/Move.toml`, add the following entry to the `package` entry:
```
published-at = "<IKA_PACKAGE_ID>"
```
and update the `ika` entry to the "<IKA_PACKAGE_ID>" as well.

In the `contracts/ika_common/Move.toml`, add the following entry to the `package` entry:
```
published-at = "<IKA_COMMON_PACKAGE_ID>"
```
and update the `ika_common` entry to the "<IKA_COMMON_PACKAGE_ID>" as well.
