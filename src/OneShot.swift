

import Foundation
import CryptoKit



@_cdecl("printAPublicKey")
public func printAPublicKey() {
    let privateKey = P384.Signing.PrivateKey()
    let publicKey = privateKey.publicKey
    let publicKeyData = publicKey.rawRepresentation

    print("Your Public key is \(publicKeyData.map { String(format: "%02x", $0) }.joined())")
}