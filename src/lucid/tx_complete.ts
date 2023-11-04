import { C } from "../core/mod.ts";
import {
  PrivateKey,
  Transaction,
  TransactionWitnesses,
  TxHash,
} from "../types/mod.ts";
import { Lucid } from "./lucid.ts";
import { TxSigned } from "./tx_signed.ts";
import { fromHex, toHex } from "../utils/mod.ts";
import { FreeableBucket, Freeables } from "../utils/freeable.ts";

export class TxComplete {
  txComplete: C.Transaction;
  witnessSetBuilder: C.TransactionWitnessSetBuilder;
  private tasks: (() => Promise<void>)[];
  private lucid: Lucid;
  fee: number;
  exUnits: { cpu: number; mem: number } | null = null;

  constructor(lucid: Lucid, tx: C.Transaction) {
    const bucket: FreeableBucket = [];
    this.lucid = lucid;
    this.txComplete = tx;
    this.witnessSetBuilder = C.TransactionWitnessSetBuilder.new();
    this.tasks = [];

    const body = tx.body();
    bucket.push(body);
    const fee = body.fee();
    bucket.push(fee);
    const witnessSet = tx.witness_set();
    bucket.push(witnessSet);

    this.fee = parseInt(fee.to_str());
    const redeemers = witnessSet.redeemers();
    bucket.push(redeemers);
    if (redeemers) {
      const exUnits = { cpu: 0, mem: 0 };
      for (let i = 0; i < redeemers.len(); i++) {
        const redeemer = redeemers.get(i);
        bucket.push(redeemer);
        const cExUnits = redeemer.ex_units();
        bucket.push(cExUnits);
        const steps = cExUnits.steps();
        bucket.push(steps);
        const mem = cExUnits.mem();
        bucket.push(mem);

        exUnits.cpu += parseInt(steps.to_str());
        exUnits.mem += parseInt(mem.to_str());
      }
      this.exUnits = exUnits;
    }

    Freeables.free(...bucket);
  }
  sign(): TxComplete {
    this.tasks.push(async () => {
      const witnesses = await this.lucid.wallet.signTx(this.txComplete);
      this.witnessSetBuilder.add_existing(witnesses);
      witnesses.free();
    });
    return this;
  }

  /** Add an extra signature from a private key. */
  signWithPrivateKey(privateKey: PrivateKey): TxComplete {
    const bucket: FreeableBucket = [];
    const priv = C.PrivateKey.from_bech32(privateKey);
    bucket.push(priv);
    const body = this.txComplete.body();
    bucket.push(body);
    const hash = C.hash_transaction(body);
    bucket.push(hash);
    const witness = C.make_vkey_witness(hash, priv);
    bucket.push(witness);
    this.witnessSetBuilder.add_vkey(witness);
    Freeables.free(...bucket);
    return this;
  }

  /** Sign the transaction and return the witnesses that were just made. */
  async partialSign(): Promise<TransactionWitnesses> {
    const witnesses = await this.lucid.wallet.signTx(this.txComplete);
    this.witnessSetBuilder.add_existing(witnesses);
    return toHex(witnesses.to_bytes());
  }

  /**
   * Sign the transaction and return the witnesses that were just made.
   * Add an extra signature from a private key.
   */
  partialSignWithPrivateKey(privateKey: PrivateKey): TransactionWitnesses {
    const priv = C.PrivateKey.from_bech32(privateKey);
    const witness = C.make_vkey_witness(
      C.hash_transaction(this.txComplete.body()),
      priv
    );
    this.witnessSetBuilder.add_vkey(witness);
    const witnesses = C.TransactionWitnessSetBuilder.new();
    witnesses.add_vkey(witness);
    return toHex(witnesses.build().to_bytes());
  }

  /** Sign the transaction with the given witnesses. */
  assemble(witnesses: TransactionWitnesses[]): TxComplete {
    witnesses.forEach((witness) => {
      const witnessParsed = C.TransactionWitnessSet.from_bytes(
        fromHex(witness)
      );
      this.witnessSetBuilder.add_existing(witnessParsed);
    });
    return this;
  }

  async complete(): Promise<TxSigned> {
    for (const task of this.tasks) {
      await task();
    }

    this.witnessSetBuilder.add_existing(this.txComplete.witness_set());
    const signedTx = C.Transaction.new(
      this.txComplete.body(),
      this.witnessSetBuilder.build(),
      this.txComplete.auxiliary_data()
    );
    return new TxSigned(this.lucid, signedTx);
  }

  /** Return the transaction in Hex encoded Cbor. */
  toString(): Transaction {
    return toHex(this.txComplete.to_bytes());
  }

  /** Return the transaction hash. */
  toHash(): TxHash {
    return C.hash_transaction(this.txComplete.body()).to_hex();
  }
}
