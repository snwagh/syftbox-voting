# Setup
- `npm init -y`
- `npm install snarkjs circomlib big-integer`
- `sudo npm uninstall -g circom`
- Install circom from source to get a version over 2.0.0
```sh
git clone https://github.com/iden3/circom.git
cd circom
cargo build --release
cargo install --path circom
```

- Test circuit generation `circom circuit.circom --r1cs --wasm`

# Run code
- Change line 228 of `index.js` to change individual votes for the 3 players (change between 0,1,2).
- Run using `node index.js`
