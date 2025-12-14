# How to sign a Bitcoin transaction using a dWallet

1. Create a dWallet and print its bitcoin public key by running the `should create a DWallet and print its bitcoin 
public key` test from the `./sign.test.ts` file.
2. Derive the Bitcoin address of this public key and load it with some bitcoins using a faucet.
3. Replace the consts at the start of the `should create a raw tx to send bitcoin from given address A to given address 
B, output the raw tx` with your dWallet public key and values of your choice, and run the test to get the TX bytes & the
TX hash bytes 