package offlinesig

import org.bouncycastle.crypto.digests.SHA256Digest

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
