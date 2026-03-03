## What this test is about

This repository checks the conformance of our code to a BCS-compatible manifest of our serialized data formats.

It does this by running a manifest generator from the code (using serde-reflection) and checking the output has not changed.

If it has in a legitimate fashion (e.g. we update one of our main types), all that's left to do is to re-run the generator and check in the change.

Here are the references to the software above:
https://github.com/diem/bcs
https://github.com/novifinancial/serde-reflection

## Examples

In this example, we will update one of our core types (IkaError), and then update the manifest:

```
huitseeker@Garillots-MBP.localdomain➜~/tmp/ika(main)» git checkout main                                                                                                                                                                                                                                                                                                                                                                                                               [7:40:40]
Already on 'main'
Your branch is up to date with 'origin/main'.
huitseeker@Garillots-MBP.localdomain➜~/tmp/ika(main)» ruplacer --subvert 'CertificateAuthorityReuse' 'CertificateAuthorityDuplicate' --go                                                                                                                                                                                                                                                                                                                                             [8:42:33]
./ika_types/src/error.rs:103 - CertificateAuthorityReuse,
./ika_types/src/error.rs:103 + CertificateAuthorityDuplicate,

./ika_types/src/messages.rs:610 - IkaError::CertificateAuthorityReuse
./ika_types/src/messages.rs:610 + IkaError::CertificateAuthorityDuplicate
./ika_types/src/messages.rs:638 - IkaError::CertificateAuthorityReuse
./ika_types/src/messages.rs:638 + IkaError::CertificateAuthorityDuplicate

./ika_core/tests/staged/ika.yaml:390 - CertificateAuthorityReuse: UNIT
./ika_core/tests/staged/ika.yaml:390 + CertificateAuthorityDuplicate: UNIT

Performed 4 replacements on 196 matching files
```

Now our code is modified in a way that will make the format test fail: let's update the manifest.

```
huitseeker@Garillots-MBP.localdomain➜~/tmp/ika(main✗)» cd ika_core                                                                                                                                                                                                                                                                                                                                                                                                                    [8:43:38]
huitseeker@Garillots-MBP.localdomain➜tmp/ika/ika_core(main✗)» cargo -q run --example generate-format -- print > tests/staged/ika.yaml
```

Let's check that we pass the test again:

```
huitseeker@Garillots-MBP.localdomain➜tmp/ika/ika_core(main✗)» cargo test format 2>&1 |tail -n 40                                                                                                                                                                                                                                                                                                                                                                                      [8:47:22]
    Finished test [unoptimized + debuginfo] target(s) in 0.35s
     Running unittests (/Users/huitseeker/tmp/ika/target/debug/deps/ika_core-5796871991341984)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 52 filtered out; finished in 0.00s

     Running tests/format.rs (/Users/huitseeker/tmp/ika/target/debug/deps/format-ecdfa91a67810be3)

running 1 test
    Finished dev [unoptimized + debuginfo] target(s) in 0.20s
     Running `target/debug/examples/generate-format test`
test test_format ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.48s
huitseeker@Garillots-MBP.localdomain➜tmp/ika/ika_core(main✗)» git status -s                                                                                                                                                                                                                                                                                                                                                                                                           [8:47:38]
 M tests/staged/ika.yaml
 M ../ika_types/src/error.rs
 M ../ika_types/src/messages.rs
```
