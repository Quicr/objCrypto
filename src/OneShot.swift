

import Foundation
import CryptoKit



@_cdecl("printAPublicKey")
public func printAPublicKey() {
    let privateKey = P384.Signing.PrivateKey()
    let publicKey = privateKey.publicKey
    let publicKeyData = publicKey.rawRepresentation

    print("Your Public key is \(publicKeyData.map { String(format: "%02x", $0) }.joined())")
}

@_cdecl("doStuffWithCharBuffer")
public func doStuffWithCharBuffer(buf: UnsafeMutableRawPointer , buflen: Int32) {

    let bTypedPtr = buf.bindMemory(to: Int8.self, capacity: Int(buflen))
    let stringBuffer = UnsafeMutableBufferPointer(start: bTypedPtr, count: Int(buflen))
    let output = Array(stringBuffer)

    if let str = String(validatingUTF8: output) {
        print("Swift got this string: \(str)")
    }else{
        print("Bad things might have been passed in to me!")
    }

    //Anyway, let us just play with the input buffer
    let charArray: [Character] = [ "C", "a", "n", " ", "C", "u","l","l","e","n",
                                   " ","r","e","a","d"," ", "t", "h", "i", "s", "?","\0" ]
    let asUInt8Array = String(charArray).utf8.map{ Int8($0) }
    var offset = 0;
    for c in asUInt8Array {
        if offset >= buflen-1{
            buf.storeBytes(of: 0x0, toByteOffset: offset, as: Int8.self)
            return
        }
        buf.storeBytes(of: c, toByteOffset: offset, as: Int8.self)
        offset += 1
    }
}