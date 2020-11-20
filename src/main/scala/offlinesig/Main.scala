package offlinesig

import java.security.SecureRandom

import org.apache.commons.lang3.ArrayUtils
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex
import org.json4s.JsonAST.JObject
import org.json4s.JsonDSL._
import org.json4s._
import org.json4s.native.JsonMethods._
import Bitcoin._

import scala.io.Source
import scala.math.BigInt

case class Signature(pub: ECPoint, r: BigInt, s: BigInt)
class Main(coin: Coin) {
  implicit val c = coin
  def mkInput(hash: String, index: Int, address: String): SigOutPoint = {
    val pubHash = Bitcoin.fromAddressToHash(address)
    SigOutPoint(pubHash, OutPoint(Message.hashFromHex(hash), index), TxOut(0, Message.makePayToPubHash(pubHash)))
  }
  def mkTxOut(value: Long, address: String) = {
    val pubHash = Bitcoin.fromAddressToHash(address)
    TxOut(value, Message.makePayToPubHash(pubHash))
  }
  def getSecret(pubHash: Bitcoin.Hash, privExt: PrivKeyExt): PrivKeyExt = {
    val mr = privExt.toPrivChild(0)
    val receive = Stream.from(0).map { i =>
      mr.toPrivChild(i)
      }
    val mc = privExt.toPrivChild(1) 
    val change = Stream.from(0).map { i =>
      mc.toPrivChild(i)
      }
    val all = (receive zip change).flatMap { case (a, b) => List(a, b) }
    // println(Hex.toHexString(pubHash))
    // println(Bitcoin.toAddressFromHash(pubHash, Bitcoin.addressPrefix))
    // all.take(10).map(c => Bitcoin.toAddress(c.toPub(), Bitcoin.addressPrefix)).foreach(println)
    all.take(100).find(c => Bitcoin.hashEqual(Bitcoin.toHash(c.toPub()), pubHash)).get
  }
  
  def sign(pub: ECPoint, secret: BigInt, hash: Bitcoin.Hash): Signature = {
    val kGen = new RFC6979KCalculator
    val signer = new ECDSASigner(kGen)

    val params = new ECPrivateKeyParameters(secret.bigInteger, Bitcoin.ecDomain)
    signer.init(true, params)
    val sig = signer.generateSignature(hash)
    val r = BigInt(sig(0))
    var s = BigInt(sig(1))
    if (s > Bitcoin.halfCurveOrder)
      s = Bitcoin.curveOrder - s
    Signature(pub, r, s)
  }

  def toCoinLeaf(priv: PrivKeyExt) = priv.toPrivChild(0x8000002C).toPrivChild(0x80000000 + coin.prefix).toPrivChild(0x80000000)
  def getMasterKey(seedFile: String, passphrase: String) = {
    val mnemonic = Source.fromFile(seedFile).getLines().mkString
    val entropy = Mnemonic.fromMnemonic(mnemonic.split(" "))
    val (_, priv) = BIP32.createFromRandom(passphrase, entropy)
    priv
  }

  def createNewSeed(entropyOpt: Option[String]) = {
    val r = new SecureRandom
    val entropy: Array[Byte] = entropyOpt map (Hex.decode(_)) getOrElse {
      val e: Array[Byte] = new Array(16)
      r.nextBytes(e)
      e }
    println(s"Entropy seed = ${Hex.toHexString(entropy)}")

    val mnemonic = Mnemonic.fromBigInt(BigInt(1, entropy), 128).mkString(" ")
    println(mnemonic)
  }

  def showMpk(seedFile: String, passphrase: String) = {
    val priv = getMasterKey(seedFile, passphrase)
    val mpk = toCoinLeaf(priv)
    val mppk = mpk.toPublic()
    val mppkJson = ("pub" -> Hex.toHexString(BIP32.getCompressed(mppk.point))) ~
    ("chain" -> Hex.toHexString(mppk.chain))
    println(compact(render(mppkJson)))
  }

  def exportXPriv(seedFile: String, passphrase: String) = {
    val priv = getMasterKey(seedFile, passphrase)
    val privExt = toCoinLeaf(priv)
    println(privExt.toSerialized())
  }

  def getMPK(mpkFile: String) = {
    val mpkJson = parse(Source.fromFile(mpkFile).getLines().mkString)
    val mpk: PublicKeyExt = (for {
      JObject(mpk) <- mpkJson
      JField("pub", JString(pubStr)) <- mpk
      JField("chain", JString(chainStr)) <- mpk
    } yield {
      val pubHex = Hex.decode(pubStr)
      val pub = Bitcoin.ecSpec.getCurve().decodePoint(pubHex)
      val chainHex = Hex.decode(chainStr)
      new PublicKeyExt(pub, chainHex)
    }).head
    mpk
  }
  def showAddresses(mpkFile: String, change: Boolean, count: Int) = {
    val mpk = getMPK(mpkFile)
    val addrStream = mpk.toPublicChild(if (change) 1 else 0).get
    val addresses = Stream.from(0).map(i => addrStream.toPublicChild(i).get).map(p => Bitcoin.toAddress(p.point, coin.prefix))
    addresses.take(count).foreach(println)
  }

  def buildTx(txFile: String) = {
    val txJson = parse(Source.fromFile(txFile).getLines().mkString)
    val JObject(tx) = txJson
    val inputs = for {
      JField("inputs", JArray(inputs)) <- tx
      JObject(input) <- inputs
      JField("tx", JString(txId)) <- input
      JField("vout", JInt(vout)) <- input
      JField("address", JString(address)) <- input
    } yield mkInput(txId, vout.toInt, address)

    val outputs = for {
      JField("outputs", JArray(outputs)) <- tx
      JObject(output) <- outputs
      JField("value", JInt(value)) <- output
      JField("address", JString(address)) <- output
    } yield mkTxOut(value.toLong, address)

    val unsignedTx = new UnsignedTx(1, 0, inputs, outputs)
    unsignedTx
  }

  def prepareTx(txFile: String) = {
    val unsignedTx = buildTx(txFile)
    val offlineTx = unsignedTx.prepareOfflineSigning()
    println(compact(render(offlineTx.map { case (pubHash, txHash) => ("pub" -> Hex.toHexString(pubHash)) ~ ("hash" -> Hex.toHexString(txHash)) })))
  }

  def signTx(seedFile: String, txFile: String, passphrase: String) = {
    val priv = getMasterKey(seedFile, passphrase)
    val mpk = toCoinLeaf(priv)

    val tx = parse(Source.fromFile(txFile).getLines().mkString)
    val sigs: Iterable[Signature] = for {
      JArray(in) <- tx
      JObject(sig) <- in
      JField("pub", JString(pubStr)) <- sig
      JField("hash", JString(hashStr)) <- sig
    } yield {
      val pubHash = Hex.decode(pubStr)
      val txHash = Hex.decode(hashStr)
      val priv = getSecret(pubHash, mpk)

      val pkey = ArrayUtils.add(BigInt(priv.secret.getD()).toUnsignedByteArray, 1.toByte)
      // println(Bitcoin.toAddressFromHash(pkey, 0x97.toByte))
      sign(priv.toPub(), priv.secret.getD(), txHash)
    }
    val sigsJson = sigs map { sig =>
      ("pub" -> Hex.toHexString(BIP32.getCompressed(sig.pub))) ~
        ("r" -> sig.r) ~ ("s" -> sig.s)
    }
    println(compact(render(sigsJson)))
  }
  def makeTx(txFile: String, sigFile: String) = {
    val unsignedTx = buildTx(txFile)

    val sigJson = parse(Source.fromFile(sigFile).getLines().mkString)
    val sigs = for {
      JArray(in) <- sigJson
      JObject(sig) <- in
      JField("pub", JString(pubStr)) <- sig
      JField("r", JInt(r)) <- sig
      JField("s", JInt(s)) <- sig
    } yield {
      val pub = Bitcoin.ecSpec.getCurve().decodePoint(Hex.decode(pubStr))
      Signature(pub, r, s)
    }
    val txSigned = unsignedTx.addSignatures(sigs)
    println(Hex.toHexString(txSigned))
  }
}

case class Coin(val prefix: Byte) {
  val hasher = Hasher.dsha
}

object Main {
  val coinPrefixes = Source.fromInputStream(Main.getClass.getResourceAsStream("/coins.txt")).getLines().map { line =>
    val x = line.split(" ")
    val Array(coin, prefix) = line.split(" ")
    coin -> Coin(Hex.decode(prefix)(0))
  }.toMap

  def main(args: Array[String]) {
    val coin = coinPrefixes(args(0))
    val m = new Main(coin)
    val command = args.lift(1)
    command map {
      case "sign" => m.signTx(args(2), args(3), args.lift(4) getOrElse "")
      case "mpk" => m.showMpk(args(2), args.lift(3) getOrElse "")
      case "export" => m.exportXPriv(args(2), args.lift(3) getOrElse "")
      case "seed" => m.createNewSeed(args.lift(2))
      case "receive" => m.showAddresses(args(2), false, args(3).toInt)
      case "change" => m.showAddresses(args(2), true, args(3).toInt)
      case "prepare" => m.prepareTx(args(2))
      case "make" => m.makeTx(args(2), args(3))
    } getOrElse {
      println("offlinesig seed [entropy] | mpk [password] | receive <mpk-file> <count> | change <mpk-file> <count> | prepare <tx-file> | sign <seed-file> <tx-file> [password] | make <tx-file> <sig-file>")
      println("tx-file: {\"inputs\": [{\"tx\": ..., \"vout\": ..., \"address\": ...}], \"outputs\": [{\"value\": ..., \"address\": ...}]} ")
      System.exit(-1)
    }
  }
}