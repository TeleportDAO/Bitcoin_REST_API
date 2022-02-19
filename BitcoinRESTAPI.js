let axios =  require('axios');
const BigNumber = require('bignumber.js');
let coinSelect = require('coinselect');
let bitcoinJS = require('bitcoinjs-lib');
let {ECPairFactory} = require('ecpair');
let ecc = require('tiny-secp256k1');
const {networks} = require('bitcoinjs-lib');
const baseURLMainnet = 'https://blockstream.info/api';
const baseURLTestnet = 'https://blockstream.info/testnet/api';
const networkMainnet = {name: 'bitcoin', ...networks.bitcoin};
const networkTestnet = {name: 'testnet', ...networks.testnet};
require('dotenv').config({path:"../.env"});
const bs58 = require('bs58');
const { BitcoinAddress } = require('bech32-buffer');
// const { loadavg } = require('os');
// const {MerkleTree} = require('merkletreejs');
// const SHA256 = require('crypto-js/sha256');

class BitcoinRESTAPI {

  constructor(_network, _baseURL, _version) {
    this.network = _network;
    this.baseURL = _baseURL;
    this.version = _version;
    this.bitcoinJS = bitcoinJS;
  }

  async findMultisigAddress (multisigAddressBeforeEncoding) {
    const bytes = Buffer.from(multisigAddressBeforeEncoding.slice(2, multisigAddressBeforeEncoding.length + 1), 'hex');
    const multisigAddress = bs58.encode(bytes);
    return multisigAddress;
  }

  async decodeBase58 (bitcoinAddress) {
    bitcoinAddress = bitcoinAddress.replace('l', 'L');
    const decodedAddress = bs58.decode(bitcoinAddress);
    const decodedAddressHex = Buffer.from(decodedAddress).toString('hex');
    return '0x' + decodedAddressHex;
  }

  async decodeBech32 (segwitAddress) {
    const address = BitcoinAddress.decode(segwitAddress);
    const hexAddress =  Buffer.from(address.data).toString('hex');
    return '0x' + hexAddress;
  }

  async deriveAddressFromPubKey (pubKey, network) {
    let {address} = this.bitcoinJS.payments.p2pkh({network: network, pubkey: Buffer.from(pubKey, 'hex')});
    return address;
  }

  async deriveAddressFromBufferPubKey (pubKey, network) {
    let {address} = this.bitcoinJS.payments.p2pkh({network: network, pubkey: pubKey});
    return address;
  }

  async getFees () {
    if (this.network.name === 'testnet') {
      return {slow: 1, average: 2, fast: 3};
    } else {
      const result = await axios.get('https://mempool.space/api/v1/fees/recommended')
      return {slow: result.data.hourFee, average: result.data.halfHourFee, fast: result.data.fastestFee}
    }
  }

  async getLatestBlock () {
    const result = await axios.get(`${this.baseURL}/blocks`);
    const blocks = result.data;
    return blocks[0];
  }

  async getTransaction (txId) {
    const result = await axios.get(`${this.baseURL}/tx/${txId}`);
    return result.data;
  }

  async getTransactionStatus (txId) { 
    const result = await axios.get(`${this.baseURL}/tx/${txId}`);
    const status = result.data.status;
    if (status.confirmed == true) {
      let txBlockNumber = status.block_height;
      let currentBlockNumber = await this.getBlockCount();
      return {
        "confirmed": true,
        "numberOfConfirmations": currentBlockNumber - txBlockNumber
      }
    } else {
      return {
        "confirmed": false,
        "numberOfConfirmations": 0
      }
    }
  }

  async getRawTransaction (txId) {
    const result = await axios.get(`${this.baseURL}/tx/${txId}/hex`);
    return result.data;
  }

  async parseTransaction (txId) {
    let rawTransaction = await this.getRawTransaction(txId);
    let result = await this.parseRawTransaction(rawTransaction);
    let version = result[0];
    let flag = result[1];
    let vin = result[2];
    let vout = result[3];
    let witness = result[4];
    let locktime = result[5];
    return {
      'version': version, 
      'flag': flag, 
      'vin': vin, 
      'vout': vout, 
      'witness': witness, 
      'locktime': locktime
    };
  }

  async getTransactions (userAddress) {
    const result = await axios.get(`${this.baseURL}/address/${userAddress}/txs`);
    return result.data;
  }

  async getTransactionHistory (userAddress, lastSeenTxId) {
    let result;
    if (lastSeenTxId == null){
      // get all transactions for userAddress
      result = await axios.get(`${this.baseURL}/address/${userAddress}/txs/chain`);
    } else {
      // get all transactions for userAddress since the last seen tx id
      result = await axios.get(`${this.baseURL}/address/${userAddress}/txs/chain/${lastSeenTxId}`);
    }
    return result.data;
  }

  async getBlock (blockNumber) {
    const blockHash = await this.getHexBlockHash(blockNumber);
    const result = await axios.get(`${this.baseURL}/block/${blockHash}`);
    return result.data;
  }

  async getMerkleProof (txId) {
    let _intermediateNodes = '';
    let transactionIndex;
    let result = await axios.get(`${this.baseURL}/tx/${txId}/merkle-proof`);
    result = result.data;
    let intermediateNodes = []

    for (let i = 0; i < result.merkle.length; i++) {
      intermediateNodes[i] = this.reverseBytes(result.merkle[i]);
    }

    for (let i = 0; i < result.merkle.length; i++) {
      _intermediateNodes = _intermediateNodes + intermediateNodes[i];
    }

    _intermediateNodes = '0x' + _intermediateNodes; 
    transactionIndex = result.pos;
  
    return {
      "intermediateNodes": _intermediateNodes,
      "transactionIndex": transactionIndex
    }
  }

  async getBlockTransactionIds (blockNumber) {
    const blockHash = await this.getHexBlockHash(blockNumber);
    const result = await axios.get(`${this.baseURL}/block/${blockHash}/txids`);
    return result.data;
  }

  reverseBytes(hexInput) {
    let inputLength = hexInput.length;
    let reversedInput = '';
    for (let i = 0; i < inputLength; i = i + 2) {
      reversedInput = reversedInput + hexInput.slice(inputLength-i-2, inputLength-i)
    }
    return reversedInput;
  }

  async getUTXOsAddress (userAddress) {
    const result = await axios.get(`${this.baseURL}/address/${userAddress}/utxo`);
    return result.data;
  }

  async getUTXOsScriptHash (scriptHash) {
    const result = await axios.get(`${this.baseURL}/scripthash/${scriptHash}/utxo`);
    return result.data;
  }

  async getHexBlockHeader (blockNumber) { 
    const hash = await this.getHexBlockHash(blockNumber);
    const result = await axios.get(`${this.baseURL}/block/${hash}/header`);
    return result.data;
	}

  async getHexBlockHash (blockNumber) {
    const result = await axios.get(`${this.baseURL}/block-height/${blockNumber}`);
		return result.data;
	}

  async getBlockCount () {
    const result = await axios.get(`${this.baseURL}/blocks/tip/height`);
		return result.data;
	}

  async getBalance (userAddress) {
    const utxos = await getUTXOsAddress(userAddress, this.baseURL);
    const balance = utxos.reduce((result, utxo) => result + utxo.value, 0) / 1e8;
    return balance;
  }

  async sendRawTransaction (rawTransaction) {
    const result = await axios.post(`${this.baseURL}/tx`, rawTransaction);
    return result.data;
  }

  async getFees () {
    if (this.network.name === 'testnet') {
      return {slow: 1, average: 2, fast: 3}
    } else {
      const result = await axios.get('https://mempool.space/api/v1/fees/recommended');
      return {slow: result.data.hourFee, average: result.data.halfHourFee, fast: result.data.fastestFee}
    }
  }

  async getDerivationPath (userAddress) {
    let allAddresses = await window.bitcoin.request({method: 'wallet_getAddresses', params: [0, 500, false]});
    for (i = 0; i < allAddresses.length; i++) {
        if (allAddresses[i].address == userAddress) {
            return allAddresses[i].derivationPath;
        }
    }
  }

  async parseRawTransaction(rawTransaction) { 
    // TODO: should be modified to support parsing of transactions that include segwit addresses
    let version = rawTransaction.slice(0, 8);
    let flag = rawTransaction.slice(8,12); //0x0001 is flag in segwit transactions
    let vinLastIndex = rawTransaction.lastIndexOf("ffffffff") + 8;
    if(vinLastIndex == 7) { // in the case that the transaction has not been finalized yet
      vinLastIndex = rawTransaction.lastIndexOf("feffffff") + 8;
    }
    let numberOfOutputsHex = rawTransaction.slice(vinLastIndex, vinLastIndex + 2);
    let numberOfOutputs = parseInt(numberOfOutputsHex, 16);;
    let outputStartIndex = vinLastIndex + 2;
    let vout = numberOfOutputsHex;
    
    let i;
    for(i = 0; i < numberOfOutputs; i++) {
      var scriptLengthHex = rawTransaction.slice(outputStartIndex + 16, outputStartIndex + 16 + 2);
      var scriptLength = parseInt(scriptLengthHex, 16)*2; // each byte = 2 hex character
      vout = vout + rawTransaction.slice(outputStartIndex, outputStartIndex + 16 + 2 + scriptLength);
      outputStartIndex = outputStartIndex + 16 + 2 + scriptLength;
    }
    let voutLastIndex = outputStartIndex;
    version = '0x' + version;
    flag = '0x' + flag;
    let vin;
    if (flag == '0x0001') {
      vin = '0x' + rawTransaction.slice(12, vinLastIndex);
    } else {
      vin = '0x' + rawTransaction.slice(8, vinLastIndex);
    }
    vout = '0x' + vout;
    let witness = '0x' + rawTransaction.slice(voutLastIndex, rawTransaction.length - 8);
    let locktime = '0x' + rawTransaction.slice(rawTransaction.length - 8, rawTransaction.length);
    return [version, flag, vin, vout, witness, locktime];
  }

  async getParsedTransaction (txId) {
    let result = await axios.get(`${this.baseURL}/tx/${txId}`);
		result = result.data;
  }

  async createUnsignedTransaction(withPrivatekey, userAddress, recipientAddresses, sendingAmounts, data){
    // create a psbt
    let network = this.network;
    let psbt = new this.bitcoinJS.Psbt({network});
    psbt.setVersion(this.version); 

    // find UTXOs
    let utxos = await this.getUTXOsAddress(userAddress);
    
    let _utxos = utxos.map((utxo) => ({
        txid: utxo.txid,
        vout: utxo.vout,
        value: utxo.value
    }));

    // define targets
    let targets = recipientAddresses.map((sendAddress, i) => ({
        address: sendAddress,
        value: sendingAmounts[i]
    }));

    // add data to targets
    const _data = Buffer.from(data, 'hex');
    const embed = this.bitcoinJS.payments.embed({ data: [_data] })
    targets.push({
      script: embed.output,
      value: 0
    })

    // fee rate (satoshis per byte)
    let feeRate = (await this.getFees()).slow; 
    // select coins to pay
    let {inputs, outputs} = await coinSelect(_utxos, targets, feeRate);

    // add input for psbt
    const inputsToSign = []
    for (const [index, input] of inputs.entries()) {
      const inputTx = await this.getTransaction(input.txid);
      const rawInputTx = await this.getRawTransaction(input.txid)
      const prevout = inputTx.vout[input.vout];
      if(!withPrivatekey){
        // get derivation path of wallet
        const {derivationPath} = await this.getDerivationPath(userAddress);
        inputsToSign.push({index, derivationPath});
      }
      psbt.addInput({ // TODO: check if it is a segwit tx or not
        // then act accordingly
        hash: input.txid,
        index: input.vout,
        nonWitnessUtxo: Buffer.from(rawInputTx, 'hex')
        // witnessUtxo: { // in case of segwit tx
        //   value: input.value,
        //   script: Buffer.from(prevout.scriptpubkey, 'hex')
        // }
      })
    }

    // add outputs for psbt
    for (let i = 0; i < outputs.length; i++) {
        let output = outputs[i];

        if (output.address != undefined) {
            psbt.addOutput({
                address: output.address,
                value: output.value
            })
        }

        if (output.address == undefined && output.script != undefined) {
            psbt.addOutput({
                address: output.address,
                script: output.script,
                value: output.value
            })
        }

        if (output.address == undefined && output.script == undefined) {
            psbt.addOutput({
                address: userAddress,
                value: output.value
            })
        }
    }
    return {psbt, inputsToSign};
  }

  async signAndSendTransaction(userAddress, recipientAddresses, sendingAmounts, data) {
    // enable window.bitcoin before proceed
    // create unsigned transaction
    let {psbt, inputsToSign} = await this.createUnsignedTransaction(
      false, 
      userAddress, 
      recipientAddresses, 
      sendingAmounts, 
      data
    );
    const psbtBase64 = psbt.toBase64();
    const signedPSBTBase64 = await window.bitcoin.request(
        {method: 'wallet_signPSBT', params: [psbtBase64, inputsToSign]}
    );
    const signedPSBT = psbt.fromBase64(signedPSBTBase64, this.network);
    signedPSBT.finalizeAllInputs();
    const rawTransaction = signedPSBT.extractTransaction().toHex();
    return this.sendRawTransaction(rawTransaction)
  }

  async signAndSendTransactionHavingPrivateKey(
    privateKey,
    recipientAddresses, 
    sendingAmounts, 
    data
  ) {
    let ECPair = ECPairFactory(ecc);
    let key = ECPair.fromWIF(privateKey, this.bitcoinJS.networks.testnet);
    let userAddress = await this.deriveAddressFromBufferPubKey(key.publicKey, this.bitcoinJS.networks.testnet);

    // create unsigned transaction
    let {psbt, _inputsToSign} = await this.createUnsignedTransaction(
      true, 
      userAddress, 
      recipientAddresses, 
      sendingAmounts, 
      data
    );

    // sign the tx
    psbt.signAllInputs(key);
    psbt.finalizeAllInputs();
    let rawTransaction = psbt.extractTransaction().toHex();
    return this.sendRawTransaction(rawTransaction)
  }

}

exports.BitcoinRESTAPI = BitcoinRESTAPI;
exports.baseURLMainnet = baseURLMainnet;
exports.baseURLTestnet = baseURLTestnet;
exports.networkMainnet = networkMainnet;
exports.networkTestnet = networkTestnet;