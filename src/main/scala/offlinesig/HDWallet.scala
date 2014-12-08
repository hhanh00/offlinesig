package offlinesig

import scala.language.implicitConversions
import java.nio.ByteBuffer
import java.security.{KeyFactory, Security}
import java.util.Arrays

import org.apache.commons.lang3.ArrayUtils
import org.bouncycastle.crypto.digests.{RIPEMD160Digest, SHA256Digest, SHA512Digest}
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.params.{ECDomainParameters, KeyParameter}
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.interfaces.ECPrivateKey
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.math.ec.ECPoint

import scala.util.{Failure, Success, Try}

object Base58 {
  private val alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  val base = 58
  /**
   * Leading zero bytes are first put aside
   * Then we do a standard mathematical conversion to base 58 using the alphabet above
   * Finally, we replace the zero bytes with '1' which are the 0 in base 58
   * Note: Without the first and third steps leading zeroes would be dropped off during roundtripping
   */
  def encode(input: Array[Byte]): String = {
    val leadingZerosTo1 = input.takeWhile(_ == 0).map(_ => "1").mkString // convert leading zero-bytes to '1's
    val os = new StringBuffer()
    val x = Iterator.iterate(BigInt(1, input)) { i: BigInt => // repeatedly pick the remainder and divider mod 58 
      val d = alphabet((i % 58).toInt) // replace with letter from alphabet
      os.append(d)
      i / 58
      }.takeWhile(_ > 0) // continue until we reach 0 - .length
      .length // forces evaluation
    leadingZerosTo1 + os.toString.reverse // step 3
  } 
  
  /**
   * Reverse the steps of the encoding
   * Leading '1' are put aside
   * Do a conversion base to base 10
   * Add leading zeroes
   */
  def decode(input: String): Array[Byte] = {
    val (leading, payload) = input.span(_ == '1') // split the leading '1's and the rest into two parts
    val b = payload.foldLeft(BigInt(0))((acc, digit) => (acc * 58 + alphabet.indexOf(digit))) // convert to base 10
    val sba = b.bigInteger.toByteArray()
    val decodePayload = BIP32.getEncoded(b) // extract to byte array - be careful of not using BigInteger.toByteArray!
    val leadingZeros: Array[Byte] = new Array(leading.length) // prepare leading zeros
    Arrays.fill(leadingZeros, 0.toByte)
    ArrayUtils.addAll(leadingZeros, decodePayload:_*) // concatenate them together
  }
}

object BIP32 {
  Security.addProvider(new BouncyCastleProvider())
  val f = KeyFactory.getInstance("ECDSA", "BC");
  val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
  val ecDomain = new ECDomainParameters(ecSpec.getCurve, ecSpec.getG, ecSpec.getN)
  
  def createFromMaster(master: Array[Byte]) = {
    val (l, r) = hmacOf("Bitcoin seed".getBytes())(master)
    val k = f.generatePrivate(new ECPrivateKeySpec(BigInt(1, l).bigInteger, ecSpec)).asInstanceOf[ECPrivateKey]
    new PrivKeyExt(k, r)
  }
  def createFromRandom(passphrase: String, entropy: Array[Byte]): (String, PrivKeyExt) = {
    val m = Mnemonic.fromBigInt(BigInt(1, entropy), entropy.length * 8)
    val seed = Mnemonic.toSeed(passphrase, m)
    val l = Arrays.copyOfRange(seed, 0, 32)
    val r = Arrays.copyOfRange(seed, 32, 64)
    val k = f.generatePrivate(new ECPrivateKeySpec(BigInt(1, l).bigInteger, ecSpec)).asInstanceOf[ECPrivateKey]
    (m.mkString(" "), new PrivKeyExt(k, r))
  }
  def getCompressed(pub: ECPoint): Array[Byte] = {
    val bb = ByteBuffer.allocate(33)
    bb.put((if (pub.getYCoord.testBitZero()) 0x03 else 0x02).toByte) // 3 if odd, 2 if even
    bb.put(pub.getXCoord().getEncoded())
    bb.array
  }
  def getEncoded(bi: BigInt): Array[Byte] = {
    val sba = bi.toByteArray
    if (sba(0) == 0) ArrayUtils.subarray(sba, 1, sba.length) else sba
  }
  
  def hmacOf(key: Array[Byte])(data: => Array[Byte]): (Array[Byte], Array[Byte]) = {
    val hmac = new HMac(new SHA512Digest)
    hmac.init(new KeyParameter(key))
    hmac.update(data, 0, data.length)
    val res: Array[Byte] = new Array(64)
    hmac.doFinal(res, 0)
    val l = Arrays.copyOfRange(res, 0, 32)
    val r = Arrays.copyOfRange(res, 32, 64)
    (l, r)
  }
}

object Bitcoin {
  implicit def richBigInt(bi: BigInt) = new RichBigInt(bi)
  class RichBigInt(bi: BigInt) {
    def toUnsignedByteArray() = {
      val r = bi.toByteArray
      if (r(0) == 0)
        ArrayUtils.subarray(r, 1, r.length)
      else
        r
    }
  }

  // val addressPrefix = 0x00.toByte
  type Hash = Array[Byte]
  type Script = Array[Byte]
  val ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1")
  val ecDomain = new ECDomainParameters(ecSpec.getCurve, ecSpec.getG, ecSpec.getN)
  val SigHashAll = 1
  
  def hashEqual(a: Hash, b: Hash) = ByteBuffer.wrap(a) == ByteBuffer.wrap(b)
  def newHash() = {
    val h: Hash = new Array(32)
    h
  }
  
  def toAddress(pub: ECPoint, prefix: Byte): String = {
    val sha = new SHA256Digest
    val pubSer = BIP32.getCompressed(pub)
    sha.update(pubSer, 0, pubSer.length)
    val shaRes: Array[Byte] = new Array(32)
    sha.doFinal(shaRes, 0)
    val ripe = new RIPEMD160Digest
    ripe.update(shaRes, 0, shaRes.length)
    val ripeRes: Array[Byte] = new Array(20)
    ripe.doFinal(ripeRes, 0)
    toAddressFromHash(ripeRes, prefix)
  }
  
  def toHash(pub: ECPoint): Hash = {
    val sha = new SHA256Digest
    val pubSer = BIP32.getCompressed(pub)
    sha.update(pubSer, 0, pubSer.length)
    val shaRes: Array[Byte] = new Array(32)
    sha.doFinal(shaRes, 0)
    val ripe = new RIPEMD160Digest
    ripe.update(shaRes, 0, shaRes.length)
    val ripeRes: Array[Byte] = new Array(20)
    ripe.doFinal(ripeRes, 0)
    ripeRes
  }
  
  def toAddressFromHash(hash: Hash, prefix: Byte): String = {
    val hashExt: Array[Byte] = new Array(hash.length + 1)
    hashExt(0) = prefix
    System.arraycopy(hash, 0, hashExt, 1, hash.length)
    val checksum = Arrays.copyOfRange(Hasher.dsha(hashExt), 0, 4)
    val addressBin = ArrayUtils.addAll(hashExt, checksum:_*)
    Base58.encode(addressBin)
  }

  def fromAddressToHash(address: String)(implicit coin: Coin): Bitcoin.Hash = {
    val h = Base58.decode(address)
    val hash = ArrayUtils.subarray(h, 1, 21)
    val recomputedAddress = toAddressFromHash(hash, coin.prefix)
    if (coin.prefix != h(0) || recomputedAddress != address)
      throw new RuntimeException("Invalid address")
    hash
  }
}

class PrivKeyExt(val secret: ECPrivateKey, val chain: Array[Byte]) {
  import offlinesig.BIP32._
  val sha512 = new SHA512Digest
  val hmac = new HMac(sha512)
  
  def toPub(): ECPoint = ecSpec.getG().multiply(secret.getD).normalize()
  def toPrivChild(index: Int) = {
    val (l, r) = hmacOf(chain) {
      val bb = ByteBuffer.allocate(37)
      if (index < 0) { // hardened key
        bb.put(0.toByte)
        bb.put(BIP32.getEncoded(secret.getD))
      }
      else {
        bb.put(BIP32.getCompressed(toPub()))
      }
      bb.putInt(index)
      bb.array      
    }

    val li = (BigInt(1, l) + secret.getD()) mod ecSpec.getN()
    val childPrivKey = f.generatePrivate(new ECPrivateKeySpec(li.bigInteger, ecSpec)).asInstanceOf[ECPrivateKey]
    new PrivKeyExt(childPrivKey, r)
  }
  
  def toPublic() = {
    new PublicKeyExt(toPub(), chain)
  }
}

class PublicKeyExt(val point: ECPoint, val chain: Array[Byte]) {
  import offlinesig.BIP32._
  val sha512 = new SHA512Digest
  val hmac = new HMac(sha512)
  def toPublicChild(index: Int): Try[PublicKeyExt] = {
    hmac.init(new KeyParameter(chain))
    if (index < 0)
      Failure(new RuntimeException("hardened key"))
    else {
      val (l, r) = hmacOf(chain) {
        val bb = ByteBuffer.allocate(37)
        bb.put(BIP32.getCompressed(point))
        bb.putInt(index)
        bb.array        
      }
      val childPoint = ecSpec.getG().multiply(BigInt(1, l).bigInteger).add(point).normalize()
      Success(new PublicKeyExt(childPoint, r))
    }
  }
}
