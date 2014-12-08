package offlinesig

import java.math.BigInteger
import java.security.SecureRandom
import java.util.Arrays

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.signers.DSAKCalculator

object Hasher {
  type Function = Array[Byte] => Array[Byte]
  
  val dsha = sha _ compose sha _
    
  def sha(data: Array[Byte]): Array[Byte] = {
    val engine = new SHA256Digest 
    engine.update(data, 0, data.length)
    val result: Array[Byte] = new Array(32)
    engine.doFinal(result, 0)
    result
  } 
}

/* Deterministic ECDSA */
class RFC6979KCalculator extends DSAKCalculator {
  case class Generator(q: BigInt, x: BigInt, m: Array[Byte]) {
    val qLen = q.bigInteger.bitLength()

    implicit def richBigInt(i: BigInt) = new {
      def toUnsignedByteArray(): Array[Byte] = {
        val x = i.toByteArray
        if (x(0) == 0)
          Arrays.copyOfRange(x, 1, x.length)
        else
          x
      }
    }

    def int2octets(x: BigInt, qLen: Int): Array[Byte] = {
      val xb = x.toUnsignedByteArray()
      val rLen = (qLen + 7) / 8
      assert(xb.length <= rLen)
      val xb2: Array[Byte] = new Array(rLen)
      System.arraycopy(xb, 0, xb2, rLen - xb.length, xb.length)
      xb2
    }

    def bits2int(b: Array[Byte], qLen: Int): BigInt = {
      val bi = BigInt(1, b)
      val l = b.length * 8
      if (l > qLen)
        bi >> (l - qLen)
      else
        bi
    }

    def bits2octet(b: Array[Byte], qLen: Int): Array[Byte] = {
      val c = bits2int(b, qLen)
      (if (c > q)
        c - q
      else c).toUnsignedByteArray()
    }

    def hmacAdd(hmac: HMac, b: Array[Byte]) = hmac.update(b, 0, b.length)

    def nextK(): BigInt = {
      val digest = new SHA256Digest()
      digest.update(m, 0, m.length)
      val h1 = Bitcoin.newHash()
      digest.doFinal(h1, 0)

//      println(Hex.toHexString(int2octets(x, qLen)))
//      println(Hex.toHexString(h1))
//      println(Hex.toHexString(bits2octet(h1, qLen)))

      val k: Array[Byte] = new Array(32)
      val v: Array[Byte] = new Array(32)

      // step b
      Arrays.fill(v, 1.toByte)
//      println(Hex.toHexString(v))

      // step c
      Arrays.fill(k, 0.toByte)
//      println(Hex.toHexString(k))

      val hmac = new HMac(new SHA256Digest())
      hmac.init(new KeyParameter(k))

      // step d
      hmac.update(v, 0, v.length)
      hmac.update(0.toByte)
      hmacAdd(hmac, int2octets(x, qLen))
      hmacAdd(hmac, bits2octet(h1, qLen))
      hmac.doFinal(k, 0)
//      println(Hex.toHexString(k))

      // step e
      hmac.init(new KeyParameter(k))
      hmac.update(v, 0, v.length)
      hmac.doFinal(v, 0)
//      println(Hex.toHexString(v))

      // step f
      hmac.update(v, 0, v.length)
      hmac.update(1.toByte)
      hmacAdd(hmac, int2octets(x, qLen))
      hmacAdd(hmac, bits2octet(h1, qLen))
      hmac.doFinal(k, 0)
//      println(Hex.toHexString(k))

      // step g
      hmac.init(new KeyParameter(k))
      hmac.update(v, 0, v.length)
      hmac.doFinal(v, 0)
//      println(Hex.toHexString(v))

      val kFinal = Iterator.continually {
        hmac.init(new KeyParameter(k))
        hmac.update(v, 0, v.length)
        hmac.doFinal(v, 0)
        val kv = bits2int(v, qLen)

        hmac.init(new KeyParameter(k))
        hmac.update(v, 0, v.length)
        hmac.update(0.toByte)
        hmac.doFinal(k, 0)

        hmac.init(new KeyParameter(k))
        hmac.update(v, 0, v.length)
        hmac.doFinal(v, 0)

//        println(s"TRY: ${Hex.toHexString(kv.toUnsignedByteArray())}")
        kv
      }.find(_ < q).get

      kFinal
    }
  }

  override def isDeterministic() = true

  var gen: Generator = _
  override def init(q: BigInteger, x: BigInteger, m: Array[Byte]): Unit = {
    gen = Generator(q, x, m)
  }

  override def init(bigInteger: BigInteger, secureRandom: SecureRandom): Unit = {
    throw new RuntimeException("Not implemented")
  }

  override def nextK(): BigInteger = gen.nextK().bigInteger
}