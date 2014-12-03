package offlinesig

import java.io.ByteArrayOutputStream

import com.google.common.io.LittleEndianDataOutputStream
import org.apache.commons.lang3.ArrayUtils
import org.bouncycastle.asn1.{ASN1Encodable, ASN1Integer, ASN1OutputStream, DLSequence}
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.math.ec.ECPoint
import org.bouncycastle.util.encoders.Hex

trait ToByteArray {
  def toByteArray() = Message.toByteArray(write)
  def write(os: LittleEndianDataOutputStream)
}

object Message {
  def hashFromHex(s: String) = {
    val h = Hex.decode(s)
    ArrayUtils.reverse(h)
    h
  }
  def hashToString(hash: Bitcoin.Hash) = {
    val h = hash.clone()
    ArrayUtils.reverse(h)
    Hex.toHexString(h)
  }
  def writeVarInt(ds: LittleEndianDataOutputStream, v: Int) = writeVarLong(ds, v.toLong)
  def writeVarLong(ds: LittleEndianDataOutputStream, v: Long) = {
    if (v > Int.MaxValue) {
      ds.write(0xFF.toByte)
      ds.writeLong(v)
    }
    else if (v > Short.MaxValue) {
      ds.write(0xFE.toByte)
      ds.writeInt(v.toInt)
    }
    else if (v >= 0xFD) {
      ds.write(0xFD.toByte)
      ds.writeShort(v.toShort)
    }
    else
      ds.write(v.toByte)
  }
  def writeScript(ds: LittleEndianDataOutputStream, s: Bitcoin.Script) {
    writeVarInt(ds, s.length)
    ds.write(s)
  }
  def toByteArray(f: LittleEndianDataOutputStream => Unit): Array[Byte] = {
    val baos = new ByteArrayOutputStream
    val os = new LittleEndianDataOutputStream(baos)
    f(os)
    os.close()
    baos.toByteArray()
  }
  def makePayToPubHash(pubHash: Bitcoin.Hash): Bitcoin.Script = {
    import offlinesig.Script._
    Message.toByteArray { os =>
      os.writeByte(OP_DUP)
      os.writeByte(OP_HASH160)
      os.writeByte(OP_DATA_20)
      os.write(pubHash)
      os.write(OP_EQUALVERIFY)
      os.write(OP_CHECKSIG)
    }
  }
  def makeSigScript(signature: Signature) = {
    val sigBytes = Message.toByteArray { os =>
      val encoder = new ASN1OutputStream(os)
      val r: ASN1Encodable = new ASN1Integer(signature.r.bigInteger)
      val s: ASN1Encodable = new ASN1Integer(signature.s.bigInteger)
      val sequence = new DLSequence(Array(r, s))
      encoder.writeObject(sequence)
      os.writeByte(Bitcoin.SigHashAll)
    }
    val pubBytes = BIP32.getCompressed(signature.pub)
    Message.toByteArray { os =>
      os.write(sigBytes.length)
      os.write(sigBytes)
      os.write(pubBytes.length)
      os.write(pubBytes)
    }
  }
}

case class SigOutPoint(pubHash: Bitcoin.Hash, outpoint: OutPoint, txout: TxOut)
class UnsignedTx(version: Int, lockTime: Int, inputs: Iterable[SigOutPoint], outputs: Iterable[TxOut]) {
  def write(index: Int)(os: LittleEndianDataOutputStream) {
    os.writeInt(version)
    Message.writeVarInt(os, inputs.size)
    for ((input, i) <- inputs.zipWithIndex) {
      val txIn = if (i == index)
        TxIn(input.outpoint, input.txout.script, -1)
      else
        TxIn(input.outpoint, Array.empty, -1)
      txIn.write(os)
    }
    Message.writeVarInt(os, outputs.size)
    for (output <- outputs) {
      output.write(os)
    }
    os.writeInt(lockTime)
    os.writeInt(Bitcoin.SigHashAll)
  }

  def prepareOfflineSigning() = {
    for ((input, i) <- inputs.zipWithIndex) yield {
      val hash = Hasher.dsha(Message.toByteArray(write(i)))
      (input.pubHash, hash)
    }
  }

  def addSignatures(sigs: Iterable[Signature]) = {
    Message.toByteArray { os =>
      os.writeInt(version)
      Message.writeVarInt(os, inputs.size)
      for ((input, signature) <- inputs zip sigs) {
        val script = Message.makeSigScript(signature)
        TxIn(input.outpoint, script, -1).write(os)
      }
      Message.writeVarInt(os, outputs.size)
      for (output <- outputs) {
        output.write(os)
      }
      os.writeInt(lockTime)
    }
  }
}

case class OutPoint(hash: Bitcoin.Hash, index: Int) extends ToByteArray {
  override def toString() = s"OutPoint(${Message.hashToString(hash)}, $index)"
  def write(ds: LittleEndianDataOutputStream) = {
    ds.write(hash)
    ds.writeInt(index)
  }
}
case class TxIn(outpoint: OutPoint, script: Bitcoin.Script, sequence: Int) extends ToByteArray {
  def write(ds: LittleEndianDataOutputStream) = {
    outpoint.write(ds)
    Message.writeScript(ds, script)
    ds.writeInt(sequence)
  }
}
case class TxOut(value: Long, script: Bitcoin.Script) extends ToByteArray {
  def write(ds: LittleEndianDataOutputStream) = {
    ds.writeLong(value)
    Message.writeScript(ds, script)
  }
}
case class Tx(hash: Bitcoin.Hash, version: Int, inputs: Vector[TxIn], outputs: Vector[TxOut], lockTime: Int) extends ToByteArray {
  def write(ds: LittleEndianDataOutputStream) = {
    ds.writeInt(version)
    Message.writeVarInt(ds, inputs.size)
    for (input <- inputs) {
      input.write(ds)
    }
    Message.writeVarInt(ds, outputs.size)
    for (output <- outputs) {
      output.write(ds)
    }
    ds.writeInt(lockTime)
  }
}

object Script {
  val OP_DUP: Byte = 118
  val OP_HASH160: Byte = -87
  val OP_DATA_20: Byte = 20
  val OP_DATA_32: Byte = 32
  val OP_EQUALVERIFY: Byte = -120
  val OP_CHECKSIG: Byte = -84
  val OP_DATA_65: Byte = 65
  val OP_EQUAL: Byte = -121
  val OP_DATA_33: Byte = 33
}