package offlinesig

import java.util.Arrays

import org.bouncycastle.crypto.digests.{SHA256Digest, SHA512Digest}
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter

import scala.io.Source

object Mnemonic {
  val chunk = BigInt(1) << 256
  val chunk11 = BigInt(1) << 11
  val wordByInt = Source.fromInputStream(getClass().getResourceAsStream("/english.txt"))
    .getLines()
    .zipWithIndex
    .map(_.swap)
    .toMap
    
  val intByWord = wordByInt.map { case (a, b) => b -> a }.toMap
  
  def fromBigInt(secret: BigInt, bitCount: Int) = {
    assert(bitCount % 32 == 0)
    val sha256 = new SHA256Digest
    val ba = BIP32.getEncoded(secret)
    assert(ba.length * 8 <= bitCount)
    val bba = if (ba.length * 8 < bitCount) {
      val ba2: Array[Byte] = new Array(bitCount / 8)
      Arrays.fill(ba2, 0.toByte)
      System.arraycopy(ba, 0, ba2, bitCount / 8 - ba.length, ba.length)
      ba2
    }
    else ba
    assert(bba.length * 8 == bitCount)
    val sha = BigInt(1, Hasher.sha(bba))
    
    val cs = bitCount / 32
    val cbi = (secret << cs) + (sha >> (256 - cs))
    assert((bitCount + cs) % 11 == 0)
    val nIterations = (bitCount + cs) / 11
    (0 until nIterations).foldLeft((cbi, Vector.empty[String])) { case ((s, words), _) =>
      val index = s mod chunk11
      val w = wordByInt(index.toInt)
      (s >> 11, words :+ w)
    }._2.reverse
  }
  
  def toSeed(passphrase: String, mnemonic: Iterable[String]): Array[Byte] = {
    val gen = new PKCS5S2ParametersGenerator(new SHA512Digest)
    val sentence = mnemonic.mkString(" ")
    val salt = "mnemonic" + passphrase
    gen.init(sentence.getBytes("UTF-8"), salt.getBytes("UTF-8"), 2048)
    gen.generateDerivedParameters(512).asInstanceOf[KeyParameter].getKey()
  }
  
  def fromMnemonic(seed: Iterable[String]) = {
    val seedBigInt = seed.map(w => intByWord(w)).foldLeft(BigInt(0))((acc, d) => acc * 2048 + d)
    val bitCount = seed.size * 11
    assert(bitCount % 33 == 0)
    val cs = bitCount / 33
    val checksum = seedBigInt & ((BigInt(1) << cs) - 1)
    val secretBigInt = seedBigInt >> cs
    val secret = BIP32.getEncoded(secretBigInt)
    val sha = BigInt(1, Hasher.sha(secret))
    val shaChecksum = (sha >> (256 - cs))
    assert(checksum == shaChecksum)
    secret    
  }
}